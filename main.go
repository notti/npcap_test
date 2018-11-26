package main

import (
	"fmt"
	"log"
	"reflect"
	"syscall"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func initDllPath() {
	h, err := syscall.LoadLibrary("kernel32.dll")
	if err != nil {
		log.Panicln("LoadLibrary", err)
	}
	defer syscall.FreeLibrary(h)
	setDllDirectory, err := syscall.GetProcAddress(h, "SetDllDirectoryA")
	if err != nil {
		// we can't do anything since SetDllDirectoryA is missing - fall back to use first wpcap.dll we encounter
		return
	}
	getSystemDirectory, err := syscall.GetProcAddress(h, "GetSystemDirectoryA")
	if err != nil {
		panic("Couldn't load GetSystemDirectoryA syscall")
	}
	buf := make([]byte, 4096)
	r, _, _ := syscall.Syscall(getSystemDirectory, 2, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0)
	if r == 0 || r > 4096-8 {
		panic("Couldn't get system directory")
	}
	copy(buf[r:], "\\Npcap")
	_, _, _ = syscall.Syscall(setDllDirectory, 1, uintptr(unsafe.Pointer(&buf[0])), 0, 0)
	// ignore errors here - we just fallback to load wpcap.dll from default locations
}

func bytePtrToString(r uintptr) string {
	bval := (*[4096]byte)(unsafe.Pointer(r))
	for i := range bval {
		if bval[i] == 0 {
			return string(bval[:i])
		}
	}
	return string(bval[:])
}

func getVersion() {
	h, err := syscall.LoadLibrary("wpcap.dll")
	if err != nil {
		log.Panicln("LoadLibrary", err)
	}
	defer syscall.FreeLibrary(h)

	pcap_lib_version, err := syscall.GetProcAddress(h, "pcap_lib_version")
	if err != nil {
		log.Panic("Couldn't load pcap_lib_version", err)
	}
	r, _, err := syscall.Syscall(pcap_lib_version, 0, 0, 0, 0)
	if r == 0 {
		log.Panic("query version failed", err)
	}
	fmt.Println(bytePtrToString(r))

}

func main() {
	getVersion()
	initDllPath()
	getVersion()

	h, err := syscall.LoadLibrary("wpcap.dll")
	if err != nil {
		log.Panicln("LoadLibrary", err)
	}
	pcapOpenOffline, err := syscall.GetProcAddress(h, "pcap_open_offline")
	if err != nil {
		log.Panic("Couldn't load pcap_open_offline", err)
	}
	pcapNextEx, err := syscall.GetProcAddress(h, "pcap_next_ex")
	if err != nil {
		log.Panic("Couldn't load pcap_next_ex", err)
	}
	fname, err := syscall.BytePtrFromString("test.pcapng")
	if err != nil {
		log.Panic("Couldn't build filename:", err)
	}
	buf := make([]byte, 4096)
	cptr, _, _ := syscall.Syscall(pcapOpenOffline, 2, uintptr(unsafe.Pointer(fname)), uintptr(unsafe.Pointer(&buf[0])), 0)
	if cptr == 0 {
		log.Panic("Couldn't open file:", buf)
	}
	var header *pcapPktHdr
	var data *byte
	var pkt []byte
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&pkt))

	for {
		ret, _, _ := syscall.Syscall(pcapNextEx, 3, cptr, uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data)))
		if ret != 1 {
			log.Panic("Error reading packet")
		}

		slice.Data = uintptr(unsafe.Pointer(data))
		slice.Len = int(header.Caplen)
		slice.Cap = int(header.Caplen)
		fmt.Println(gopacket.NewPacket(pkt, layers.LayerTypeEthernet, gopacket.NoCopy).Dump())
	}
}
