// +build ignore

package main

//#include <pcap.h>
import "C"

type timeval C.struct_timeval
type pcapPktHdr C.struct_pcap_pkthdr
type bytePtr *C.u_char

const pcapErrorNotActivated = C.PCAP_ERROR_NOT_ACTIVATED
