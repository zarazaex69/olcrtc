package crypto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"sync"
	"testing"
)

const (
	testPSK        = "01234567890123456789012345678901"
	testDataAAD    = "olcrtc/muxconn/v2/data"
	testControlAAD = "olcrtc/muxconn/v2/control"
)

func newKeyPair(tb testing.TB) (*KeySet, *KeySet) {
	tb.Helper()
	client, err := NewKeySet([]byte(testPSK), Client)
	if err != nil {
		tb.Fatalf("NewKeySet(client) error = %v", err)
	}
	server, err := NewKeySet([]byte(testPSK), Server)
	if err != nil {
		tb.Fatalf("NewKeySet(server) error = %v", err)
	}
	return client, server
}

func TestNewKeySetRejectsInvalidInput(t *testing.T) {
	if _, err := NewKeySet([]byte("short"), Client); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("short PSK error = %v, want %v", err, ErrInvalidKeySize)
	}
	if _, err := NewKeySet([]byte(testPSK), Role(99)); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("invalid role error = %v, want %v", err, ErrInvalidRole)
	}
}

func TestDirectionalRoundTrip(t *testing.T) {
	client, server := newKeyPair(t)
	testDirection(t, client, server, "client to server")
	testDirection(t, server, client, "server to client")
}

func testDirection(t *testing.T, sender, receiver *KeySet, payload string) {
	t.Helper()
	record, err := sender.Seal([]byte(payload), []byte(testDataAAD))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	got, err := receiver.Open(record, []byte(testDataAAD))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if string(got) != payload {
		t.Fatalf("Open() = %q, want %q", got, payload)
	}
}

func TestReflectedRecordFailsAuthentication(t *testing.T) {
	client, _ := newKeyPair(t)
	record, err := client.Seal([]byte("reflect"), []byte(testDataAAD))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if _, err := client.Open(record, []byte(testDataAAD)); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("Open(reflection) error = %v, want %v", err, ErrAuthentication)
	}
}

func TestPlaneAADIsolation(t *testing.T) {
	client, server := newKeyPair(t)
	data, err := client.Seal([]byte("data"), []byte(testDataAAD))
	if err != nil {
		t.Fatalf("Seal(data) error = %v", err)
	}
	if _, openErr := server.Open(data, []byte(testControlAAD)); !errors.Is(openErr, ErrAuthentication) {
		t.Fatalf("Open(data as control) error = %v, want %v", openErr, ErrAuthentication)
	}
	if _, openErr := server.Open(data, []byte(testDataAAD)); openErr != nil {
		t.Fatalf("Open(data) after AAD failure error = %v", openErr)
	}

	control, err := client.Seal([]byte("control"), []byte(testControlAAD))
	if err != nil {
		t.Fatalf("Seal(control) error = %v", err)
	}
	if _, err := server.Open(control, []byte(testDataAAD)); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("Open(control as data) error = %v, want %v", err, ErrAuthentication)
	}
	if _, err := server.Open(control, []byte(testControlAAD)); err != nil {
		t.Fatalf("Open(control) after AAD failure error = %v", err)
	}
}

func TestRecordLayoutAndBufferAPI(t *testing.T) {
	client, server := newKeyPair(t)
	dst := make([]byte, 3, 3+WireOverhead+7)
	copy(dst, "pre")
	sealed, err := client.SealInto(dst, []byte("payload"), []byte(testDataAAD))
	if err != nil {
		t.Fatalf("SealInto() error = %v", err)
	}
	record := sealed[3:]
	if len(record) != WireOverhead+len("payload") {
		t.Fatalf("record size = %d, want %d", len(record), WireOverhead+len("payload"))
	}
	if string(record[:len(recordMagic)]) != recordMagic {
		t.Fatalf("magic = %q, want %q", record[:len(recordMagic)], recordMagic)
	}
	if counter := binary.BigEndian.Uint64(record[len(recordMagic):]); counter != 1 {
		t.Fatalf("counter = %d, want 1", counter)
	}
	opened, err := server.OpenInto([]byte("pre"), record, []byte(testDataAAD))
	if err != nil {
		t.Fatalf("OpenInto() error = %v", err)
	}
	if string(opened) != "prepayload" {
		t.Fatalf("OpenInto() = %q, want %q", opened, "prepayload")
	}
}

func TestReplayDuplicate(t *testing.T) {
	client, server := newKeyPair(t)
	record, err := client.Seal([]byte("once"), []byte(testDataAAD))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if _, err := server.Open(record, []byte(testDataAAD)); err != nil {
		t.Fatalf("first Open() error = %v", err)
	}
	if _, err := server.Open(record, []byte(testDataAAD)); !errors.Is(err, ErrReplayDuplicate) {
		t.Fatalf("second Open() error = %v, want %v", err, ErrReplayDuplicate)
	}
}

func TestReplayAcceptsOutOfOrderAcrossPlanes(t *testing.T) {
	client, server := newKeyPair(t)
	data, err := client.Seal([]byte("one"), []byte(testDataAAD))
	if err != nil {
		t.Fatalf("Seal(data) error = %v", err)
	}
	control, err := client.Seal([]byte("two"), []byte(testControlAAD))
	if err != nil {
		t.Fatalf("Seal(control) error = %v", err)
	}
	if _, err := server.Open(control, []byte(testControlAAD)); err != nil {
		t.Fatalf("Open(counter 2) error = %v", err)
	}
	if _, err := server.Open(data, []byte(testDataAAD)); err != nil {
		t.Fatalf("Open(counter 1) error = %v", err)
	}
}

func TestReplayRejectsRecordOlderThanWindow(t *testing.T) {
	client, server := newKeyPair(t)
	records := make([][]byte, replayWindowSize+1)
	for i := range records {
		var err error
		records[i], err = client.Seal([]byte("record"), []byte(testDataAAD))
		if err != nil {
			t.Fatalf("Seal(%d) error = %v", i, err)
		}
	}
	if _, err := server.Open(records[len(records)-1], []byte(testDataAAD)); err != nil {
		t.Fatalf("Open(newest) error = %v", err)
	}
	if _, err := server.Open(records[0], []byte(testDataAAD)); !errors.Is(err, ErrReplayTooOld) {
		t.Fatalf("Open(oldest) error = %v, want %v", err, ErrReplayTooOld)
	}
}

func TestServerAcceptsIndependentClientPrefixes(t *testing.T) {
	clientA, server := newKeyPair(t)
	clientB, err := NewKeySet([]byte(testPSK), Client)
	if err != nil {
		t.Fatalf("NewKeySet(client B) error = %v", err)
	}
	for name, client := range map[string]*KeySet{"a": clientA, "b": clientB} {
		record, sealErr := client.Seal([]byte(name), []byte(testDataAAD))
		if sealErr != nil {
			t.Fatalf("Seal(client %s) error = %v", name, sealErr)
		}
		if _, openErr := server.Open(record, []byte(testDataAAD)); openErr != nil {
			t.Fatalf("Open(client %s) error = %v", name, openErr)
		}
	}
	if len(server.replay.senders) != 2 {
		t.Fatalf("sender states = %d, want 2", len(server.replay.senders))
	}
}

func TestReplayStateUsesBoundedLRU(t *testing.T) {
	_, server := newKeyPair(t)
	for i := 0; i <= maxReplaySenders; i++ {
		client, err := NewKeySet([]byte(testPSK), Client)
		if err != nil {
			t.Fatalf("NewKeySet(client %d) error = %v", i, err)
		}
		binary.BigEndian.PutUint64(client.send.prefix[noncePrefixSize-8:], uint64(i))
		record, err := client.Seal(nil, []byte(testDataAAD))
		if err != nil {
			t.Fatalf("Seal(client %d) error = %v", i, err)
		}
		if _, err := server.Open(record, []byte(testDataAAD)); err != nil {
			t.Fatalf("Open(client %d) error = %v", i, err)
		}
	}
	if len(server.replay.senders) != maxReplaySenders {
		t.Fatalf("sender states = %d, want %d", len(server.replay.senders), maxReplaySenders)
	}
	var first [noncePrefixSize]byte
	if _, ok := server.replay.senders[replayKey{prefix: first, aad: aadTag([]byte(testDataAAD))}]; ok {
		t.Fatal("least-recently-used sender was not evicted")
	}
}

func TestOpenRejectsMalformedRecords(t *testing.T) {
	client, server := newKeyPair(t)
	for _, size := range []int{0, 1, WireOverhead - 1} {
		if _, err := server.Open(make([]byte, size), []byte(testDataAAD)); !errors.Is(err, ErrRecordTooShort) {
			t.Fatalf("Open(size %d) error = %v, want %v", size, err, ErrRecordTooShort)
		}
	}
	record, err := client.Seal([]byte("payload"), []byte(testDataAAD))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	badMagic := bytes.Clone(record)
	badMagic[0] ^= 0xff
	if _, err := server.Open(badMagic, []byte(testDataAAD)); !errors.Is(err, ErrBadRecordMagic) {
		t.Fatalf("Open(bad magic) error = %v, want %v", err, ErrBadRecordMagic)
	}
	if _, err := server.Open(record[:len(record)-1], []byte(testDataAAD)); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("Open(truncated tag) error = %v, want %v", err, ErrAuthentication)
	}
}

func TestConcurrentSealAndOpen(t *testing.T) {
	client, server := newKeyPair(t)
	const workers = replayWindowSize
	records := make([][]byte, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := range workers {
		go func() {
			defer wg.Done()
			var err error
			records[i], err = client.Seal([]byte("record"), []byte(testDataAAD))
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	wg.Add(workers)
	for i := range workers {
		go func() {
			defer wg.Done()
			if _, err := server.Open(records[i], []byte(testDataAAD)); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent record error = %v", err)
	}
}

func TestCounterExhaustionDoesNotWrap(t *testing.T) {
	client, _ := newKeyPair(t)
	client.send.counter.Store(math.MaxUint64 - 1)
	record, err := client.Seal(nil, []byte(testDataAAD))
	if err != nil {
		t.Fatalf("Seal(max counter) error = %v", err)
	}
	if counter := binary.BigEndian.Uint64(record[len(recordMagic):]); counter != math.MaxUint64 {
		t.Fatalf("counter = %d, want %d", counter, uint64(math.MaxUint64))
	}
	if _, err := client.Seal(nil, []byte(testDataAAD)); !errors.Is(err, ErrCounterExhausted) {
		t.Fatalf("Seal(after max) error = %v, want %v", err, ErrCounterExhausted)
	}
}

func BenchmarkSealInto(b *testing.B) {
	client, _ := newKeyPair(b)
	payload := bytes.Repeat([]byte{0xab}, 12*1024)
	buf := make([]byte, 0, len(payload)+WireOverhead)
	aad := []byte(testDataAAD)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for range b.N {
		if _, err := client.SealInto(buf[:0], payload, aad); err != nil {
			b.Fatalf("SealInto() error = %v", err)
		}
	}
}

func BenchmarkRecordRoundTrip(b *testing.B) {
	client, server := newKeyPair(b)
	payload := bytes.Repeat([]byte{0xab}, 12*1024)
	aad := []byte(testDataAAD)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for range b.N {
		record, err := client.Seal(payload, aad)
		if err != nil {
			b.Fatalf("Seal() error = %v", err)
		}
		if _, err := server.Open(record, aad); err != nil {
			b.Fatalf("Open() error = %v", err)
		}
	}
}

func TestOpenKeepsIndependentWindowsPerAAD(t *testing.T) {
	client, server := newKeyPair(t)
	control, err := client.Seal([]byte("control"), []byte(testControlAAD))
	if err != nil {
		t.Fatalf("Seal(control) error = %v", err)
	}
	for i := range replayWindowSize * 2 {
		data, sealErr := client.Seal([]byte("data"), []byte(testDataAAD))
		if sealErr != nil {
			t.Fatalf("Seal(data %d) error = %v", i, sealErr)
		}
		if _, openErr := server.Open(data, []byte(testDataAAD)); openErr != nil {
			t.Fatalf("Open(data %d) error = %v", i, openErr)
		}
	}
	if _, err := server.Open(control, []byte(testControlAAD)); err != nil {
		t.Fatalf("Open(control) after %d data records error = %v", replayWindowSize*2, err)
	}
}
