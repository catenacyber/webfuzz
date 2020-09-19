package main

import (
	"reflect"
	"unsafe"

	"github.com/catenacyber/webfuzz/webfuzz"
)

// #cgo CFLAGS: -Wall -Werror
// #ifdef __linux__
// __attribute__((weak, section("__libfuzzer_extra_counters")))
// #else
// #error Currently only Linux is supported
// #endif
// unsigned char LibfuzzerExtraCounters[0x10000];
import "C"

//export LLVMFuzzerInitialize
func LLVMFuzzerInitialize(argc uintptr, argv uintptr) int {
	webfuzz.WebfuzzInitialize(unsafe.Pointer(&C.LibfuzzerExtraCounters[0]), 0x10000)
	return 0
}

//export LLVMFuzzerTestOneInput
func LLVMFuzzerTestOneInput(data uintptr, size uint64) int {
	sh := &reflect.SliceHeader{
		Data: data,
		Len:  int(size),
		Cap:  int(size),
	}
	input := *(*[]byte)(unsafe.Pointer(sh))
	webfuzz.WebfuzzProcess(input)
	// always return 0 as it is expected by libFuzzer
	return 0
}

func main() {}
