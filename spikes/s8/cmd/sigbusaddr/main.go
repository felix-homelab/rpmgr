// SPDX-License-Identifier: Apache-2.0

// Command sigbusaddr checks which fault address a process sees when it touches a memory-mapped
// file page after the file was truncated (SIGBUS). modernc.org/sqlite's SEH emulation recovers
// such a fault only if the address lies in the wal-index mapping, so an emulator that reports 0
// makes its test TestSEHTruncatedShm fail without any defect in the driver. Spike S8.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"syscall"
	"unsafe"
)

func main() {
	dir, err := os.MkdirTemp("", "sigbusaddr-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "f")
	const size = 32768
	if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
		panic(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		panic(err)
	}
	mem, err := syscall.Mmap(int(f.Fd()), 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		panic(err)
	}
	base := uintptr(unsafe.Pointer(&mem[0]))
	if err := f.Truncate(0); err != nil {
		panic(err)
	}
	target := base + 4096

	debug.SetPanicOnFault(true)
	defer func() {
		e := recover()
		type faultAddr interface{ Addr() uintptr }
		fa, ok := e.(faultAddr)
		if !ok {
			fmt.Printf("%s/%s: no fault address in panic value %v\n", runtime.GOOS, runtime.GOARCH, e)
			os.Exit(1)
		}
		verdict := "correct"
		if fa.Addr() != target {
			verdict = "WRONG"
		}
		fmt.Printf("%s/%s: touched %#x, mapping %#x, fault address reported %#x: %s\n",
			runtime.GOOS, runtime.GOARCH, target, base, fa.Addr(), verdict)
		if verdict != "correct" {
			os.Exit(1)
		}
	}()
	sink = mem[4096] // the page is beyond the truncated file's end: SIGBUS
	fmt.Println("no fault")
	os.Exit(2)
}

// sink keeps the faulting load from being optimised away.
var sink byte
