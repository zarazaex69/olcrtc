// Package crypto implements the olcrtc v2 encrypted record layer.
//
// Each KeySet derives independent client-to-server and server-to-client keys
// from one PSK. Records use XChaCha20-Poly1305 with a random sender prefix and
// monotonic counter. Authenticated records pass through a bounded per-prefix
// replay window shared by every connection using the KeySet.
package crypto

import (
	"container/list"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	clientToServerLabel = "olcrtc/v2/client-to-server"
	serverToClientLabel = "olcrtc/v2/server-to-client"
	recordMagic         = "OLC2"
	noncePrefixSize     = chacha20poly1305.NonceSizeX - 8
	recordHeaderSize    = len(recordMagic) + 8 + noncePrefixSize
	replayWindowSize    = 64
	maxReplaySenders    = 256

	// WireOverhead is magic, counter, sender prefix, and authentication tag.
	WireOverhead = recordHeaderSize + chacha20poly1305.Overhead
)

//nolint:gochecknoglobals,nolintlint // exported sentinel errors are stable API values
var (
	// ErrInvalidKeySize is returned when the PSK is not 32 bytes.
	ErrInvalidKeySize = errors.New("invalid key size")
	// ErrInvalidRole is returned when a KeySet role is unsupported.
	ErrInvalidRole = errors.New("invalid crypto role")
	// ErrRecordTooShort is returned when a record cannot contain the v2 header and tag.
	ErrRecordTooShort = errors.New("record too short")
	// ErrBadRecordMagic is returned when a record is not an olcrtc v2 record.
	ErrBadRecordMagic = errors.New("bad record magic")
	// ErrInvalidCounter is returned when a sender emits reserved counter zero.
	ErrInvalidCounter = errors.New("invalid record counter")
	// ErrAuthentication is returned when record authentication fails.
	ErrAuthentication = errors.New("record authentication failed")
	// ErrReplayDuplicate is returned when an authenticated record was already accepted.
	ErrReplayDuplicate = errors.New("duplicate record")
	// ErrReplayTooOld is returned when an authenticated record is outside the replay window.
	ErrReplayTooOld = errors.New("record too old")
	// ErrCounterExhausted is returned instead of wrapping the sender counter.
	ErrCounterExhausted = errors.New("record counter exhausted")
)

var noncePool = sync.Pool{ //nolint:gochecknoglobals // fixed-size AEAD nonce scratch is shared across key sets
	New: func() any {
		return new([chacha20poly1305.NonceSizeX]byte)
	},
}

func acquireNonce() *[chacha20poly1305.NonceSizeX]byte {
	nonce, ok := noncePool.Get().(*[chacha20poly1305.NonceSizeX]byte)
	if ok {
		return nonce
	}
	return new([chacha20poly1305.NonceSizeX]byte)
}

// Role selects the directional send and receive keys.
type Role uint8

const (
	// Client sends with the client-to-server key and receives with the reverse key.
	Client Role = iota + 1
	// Server sends with the server-to-client key and receives with the reverse key.
	Server
)

// String returns the role name used in diagnostics.
func (r Role) String() string {
	switch r {
	case Client:
		return "client"
	case Server:
		return "server"
	default:
		return fmt.Sprintf("role(%d)", r)
	}
}

type sealState struct {
	aead    cipher.AEAD
	prefix  [noncePrefixSize]byte
	counter atomic.Uint64
}

type replayKey struct {
	prefix [noncePrefixSize]byte
	aad    uint64
}

type replayState struct {
	key     replayKey
	highest uint64
	seen    uint64
	element *list.Element
}

type replayCache struct {
	mu      sync.Mutex
	senders map[replayKey]*replayState
	lru     list.List
}

func aadTag(aad []byte) uint64 {
	const (
		offsetBasis = 14695981039346656037
		prime       = 1099511628211
	)
	tag := uint64(offsetBasis)
	for _, b := range aad {
		tag ^= uint64(b)
		tag *= prime
	}
	return tag
}

// KeySet owns one directional sender and shared receive replay state.
// It is safe for concurrent use and should be reused across data, control,
// peer, and reconnect muxconn instances for one process role.
type KeySet struct {
	send    sealState
	receive cipher.AEAD
	replay  replayCache
}

// NewKeySet derives directional v2 keys from a 32-byte PSK and selects them by role.
func NewKeySet(psk []byte, role Role) (*KeySet, error) {
	if len(psk) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("new key set: %w: got %d", ErrInvalidKeySize, len(psk))
	}
	clientKey, err := deriveKey(psk, clientToServerLabel)
	if err != nil {
		return nil, err
	}
	serverKey, err := deriveKey(psk, serverToClientLabel)
	if err != nil {
		return nil, err
	}
	return newKeySetForRole(clientKey, serverKey, role)
}

func deriveKey(psk []byte, label string) ([chacha20poly1305.KeySize]byte, error) {
	var key [chacha20poly1305.KeySize]byte
	if _, err := io.ReadFull(hkdf.New(sha256.New, psk, nil, []byte(label)), key[:]); err != nil {
		return key, fmt.Errorf("derive %s key: %w", label, err)
	}
	return key, nil
}

func newKeySetForRole(clientKey, serverKey [chacha20poly1305.KeySize]byte, role Role) (*KeySet, error) {
	var sendKey, receiveKey []byte
	switch role {
	case Client:
		sendKey, receiveKey = clientKey[:], serverKey[:]
	case Server:
		sendKey, receiveKey = serverKey[:], clientKey[:]
	default:
		return nil, fmt.Errorf("new key set: %w: %d", ErrInvalidRole, role)
	}
	sendAEAD, err := chacha20poly1305.NewX(sendKey)
	if err != nil {
		return nil, fmt.Errorf("create send AEAD: %w", err)
	}
	receiveAEAD, err := chacha20poly1305.NewX(receiveKey)
	if err != nil {
		return nil, fmt.Errorf("create receive AEAD: %w", err)
	}
	keys := &KeySet{
		send:    sealState{aead: sendAEAD},
		receive: receiveAEAD,
		replay:  replayCache{senders: make(map[replayKey]*replayState, maxReplaySenders)},
	}
	if _, err := rand.Read(keys.send.prefix[:]); err != nil {
		return nil, fmt.Errorf("seed sender nonce prefix: %w", err)
	}
	return keys, nil
}

// Seal allocates and seals one v2 record with aad.
func (k *KeySet) Seal(plaintext, aad []byte) ([]byte, error) {
	return k.SealInto(nil, plaintext, aad)
}

// SealInto appends one v2 record to dst. The record layout is:
// magic "OLC2" | counter uint64 big-endian | sender prefix [16]byte | ciphertext | tag.
func (k *KeySet) SealInto(dst, plaintext, aad []byte) ([]byte, error) {
	counter, err := k.send.nextCounter()
	if err != nil {
		return nil, err
	}
	base := len(dst)
	recordLen := recordHeaderSize + len(plaintext) + k.send.aead.Overhead()
	out := appendSpace(dst, recordLen)
	header := out[base : base+recordHeaderSize]
	copy(header, recordMagic)
	binary.BigEndian.PutUint64(header[len(recordMagic):], counter)
	copy(header[len(recordMagic)+8:], k.send.prefix[:])

	nonce := acquireNonce()
	copy(nonce[:noncePrefixSize], k.send.prefix[:])
	binary.BigEndian.PutUint64(nonce[noncePrefixSize:], counter)
	sealed := k.send.aead.Seal(out[:base+recordHeaderSize], nonce[:], plaintext, aad)
	noncePool.Put(nonce)
	return sealed, nil
}

func appendSpace(dst []byte, size int) []byte {
	if cap(dst)-len(dst) >= size {
		return dst[:len(dst)+size]
	}
	return append(dst, make([]byte, size)...)
}

func (s *sealState) nextCounter() (uint64, error) {
	for {
		current := s.counter.Load()
		if current == math.MaxUint64 {
			return 0, fmt.Errorf("seal record: %w", ErrCounterExhausted)
		}
		if s.counter.CompareAndSwap(current, current+1) {
			return current + 1, nil
		}
	}
}

// Open allocates and authenticates one v2 record with aad.
func (k *KeySet) Open(record, aad []byte) ([]byte, error) {
	return k.OpenInto(nil, record, aad)
}

// OpenInto appends authenticated plaintext to dst, then records the counter in
// the shared replay window. Failed authentication never mutates replay state.
func (k *KeySet) OpenInto(dst, record, aad []byte) ([]byte, error) {
	if len(record) < WireOverhead {
		return nil, fmt.Errorf("open record: %w: got %d", ErrRecordTooShort, len(record))
	}
	if string(record[:len(recordMagic)]) != recordMagic {
		return nil, fmt.Errorf("open record: %w", ErrBadRecordMagic)
	}
	counter := binary.BigEndian.Uint64(record[len(recordMagic):])
	if counter == 0 {
		return nil, fmt.Errorf("open record: %w", ErrInvalidCounter)
	}
	var prefix [noncePrefixSize]byte
	copy(prefix[:], record[len(recordMagic)+8:recordHeaderSize])
	nonce := acquireNonce()
	copy(nonce[:noncePrefixSize], prefix[:])
	binary.BigEndian.PutUint64(nonce[noncePrefixSize:], counter)

	plaintext, err := k.receive.Open(dst, nonce[:], record[recordHeaderSize:], aad)
	noncePool.Put(nonce)
	if err != nil {
		return nil, fmt.Errorf("open record: %w", ErrAuthentication)
	}
	if err := k.replay.accept(replayKey{prefix: prefix, aad: aadTag(aad)}, counter); err != nil {
		return nil, fmt.Errorf("open record: %w", err)
	}
	return plaintext, nil
}

func (r *replayCache) accept(key replayKey, counter uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.senders[key]
	if state == nil {
		r.insert(key, counter)
		return nil
	}
	if counter > state.highest {
		shift := counter - state.highest
		if shift >= replayWindowSize {
			state.seen = 1
		} else {
			state.seen = state.seen<<shift | 1
		}
		state.highest = counter
		r.lru.MoveToFront(state.element)
		return nil
	}
	age := state.highest - counter
	if age >= replayWindowSize {
		return ErrReplayTooOld
	}
	mask := uint64(1) << age
	if state.seen&mask != 0 {
		return ErrReplayDuplicate
	}
	state.seen |= mask
	r.lru.MoveToFront(state.element)
	return nil
}

func (r *replayCache) insert(key replayKey, counter uint64) {
	if len(r.senders) >= maxReplaySenders {
		oldest := r.lru.Back()
		state, ok := oldest.Value.(*replayState)
		if ok {
			delete(r.senders, state.key)
		}
		r.lru.Remove(oldest)
	}
	state := &replayState{key: key, highest: counter, seen: 1}
	state.element = r.lru.PushFront(state)
	r.senders[key] = state
}
