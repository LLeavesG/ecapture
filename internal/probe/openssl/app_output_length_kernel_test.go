package openssl

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// Opt-in live test: production bytecode attaches only to this test's child.
// Android uses the same checked-in fixture cross-compiled with its NDK.
func TestKernelOutputLength(t *testing.T) {
	object := os.Getenv("ECAPTURE_TEST_BPF_OBJECT")
	if object == "" {
		t.Skip("set ECAPTURE_TEST_BPF_OBJECT to native-architecture bytecode")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	for name := range spec.Programs {
		if name != "probe_entry_app_data_0" && name != "probe_ret_app_data_0" {
			delete(spec.Programs, name)
		}
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Fatalf("load production probes: %+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	hook := ApplicationDataHook{Direction: AppDataDirectionWrite, CaptureOn: AppDataCaptureReturn,
		BufferArg: 2, ContextArg: 1, LengthSource: AppDataLengthOutput, LengthArg: 4,
		LengthSize: 8, ReturnSuccessValue: 1, MaxBytes: 4096}
	config, key := hook.bpfConfig(), uint32(0)
	if err := collection.Maps["app_hook_configs"].Update(&key, &config, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	reader, err := perf.NewReader(collection.Maps["app_data_events"], 8*os.Getpagesize())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	exe := os.Getenv("ECAPTURE_TEST_FIXTURE")
	if exe == "" {
		exe = filepath.Join(t.TempDir(), "fixture")
		if out, err := exec.Command("cc", "-O0", "-g", "-o", exe, "testdata/output_length_fixture.c").CombinedOutput(); err != nil {
			t.Fatalf("fixture: %v: %s", err, out)
		}
	}
	child := exec.Command(exe)
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	ready := make([]byte, 6)
	if _, err := io.ReadFull(stdout, ready); err != nil || string(ready) != "ready\n" {
		t.Fatalf("fixture readiness: %q %v", ready, err)
	}
	binary, err := link.OpenExecutable(exe)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := binary.Uprobe("fixture_write_ex", collection.Programs["probe_entry_app_data_0"],
		&link.UprobeOptions{PID: child.Process.Pid})
	if err != nil {
		t.Fatal(err)
	}
	defer entry.Close()
	ret, err := binary.Uretprobe("fixture_write_ex", collection.Programs["probe_ret_app_data_0"],
		&link.UprobeOptions{PID: child.Process.Pid})
	if err != nil {
		t.Fatal(err)
	}
	defer ret.Close()
	if _, err := io.WriteString(stdin, "\n"); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	reader.SetDeadline(time.Now().Add(time.Second))
	events := 0
	for {
		record, err := reader.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			break
		}
		if err != nil || record.LostSamples != 0 {
			t.Fatalf("read: %v, loss: %d", err, record.LostSamples)
		}
		event := new(ApplicationDataEvent)
		if err := event.DecodeFromBytes(record.RawSample); err != nil {
			t.Fatal(err)
		}
		if event.OriginalLen != 7 || event.ContextID != 0x1234 || string(event.Data[:event.DataLen]) != "payload" {
			t.Fatalf("wrong accepted bytes: %+v", event)
		}
		events++
	}
	if events != 1 {
		t.Fatalf("four calls must produce one exact 7-byte event; got %d", events)
	}
}
