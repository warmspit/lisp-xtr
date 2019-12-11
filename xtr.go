// ---------------------------------------------------------------------------
//
// Copyright 2013-2019 lispers.net - Dino Farinacci <farinacci@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// ---------------------------------------------------------------------------
//
// xtr.go
//
// This file contains LISP ITR, RTR, and ETR functions that can encapsulate and
// decapsulate packets faster than the python code lisp-itr.py, lisp-etr.py,
// and lisp-rtr.py.
//
// This is a external data-plane from the lispers.net control-plane perspective
// and must be run with "lisp xtr-parameters" sub-command "ipc-data-plane =
// yes".
//
// Todo list:
// (1) Do lisp-crytpo.
// (2) Make sure we add encap-port for both NAT-traversal and lisp-crypto.
// (3) Look at alternative to gopacket.NewPacketSource(). Gopi says use
//     static buffer. GC will kill you.
// (4) Fix decap forwarding for IPv6 EIDs. Test IPv6 RLOCs.
//
// ---------------------------------------------------------------------------

package main

import "fmt"
import "os"
import "strings"
import "strconv"
import "syscall"
import "time"
import "net"
import "unsafe"
import "math/rand"
import "encoding/binary"
import "crypto/hmac"
import "github.com/google/gopacket"
import "github.com/google/gopacket/pcap"
import "github.com/google/gopacket/layers"
import "github.com/google/gopacket/afpacket"
import "golang.org/x/net/bpf"

//
// ---------- Global Variables ----------
//
var lispRTR = false
var lispEncapSocket [2]int
var lispDecapSocket *net.UDPConn
var lispUseAFpacket = false

//
// Prebuild LISP and UDP headers. And IPv4 and IPv6 outer headers.
//
var lispHeader []byte
var lispUDPheader []byte
var lispIPv4header []byte
var lispIPv6header []byte

//
// main
//
// Main entry point for xtr.go that runs in binary file lisp-xtr.
//
func main() {
	if !lispXTRstartup() {
		return
	}

	//
	// Run thread to process IPC messages from the lispers.net control-plane.
	//
	lispIPCmessageProcessing()

	//
	// If we return, return resources.
	//
	lispXTRshutdown()
}

//
// lispXTRstartup
//
// Initialize the process and start forwarding threads. Run thread to listen
// for IPC messages from the lispers.net python code.
//
func lispXTRstartup() bool {
	hostname, _ := os.Hostname()
	hostname = strings.Split(hostname, ".")[0]
	ts := lispCommandOutput("date")
	version := lispReadFile("./lisp-version.txt")

	lprint("lispers.net LISP xTR starting up %s, version %s, hostname %s", ts,
		version, bold(hostname))

	//
	// Initialize pre-built headers.
	//
	lispBuildHeaders()

	//
	// Initialize the decap stats slice.
	//
	lispDecapStats = make(map[string]*lispStats)

	//
	// Should we use AF_PACKET interface. Check command line.
	//
	if len(os.Args) >= 2 {
		lispUseAFpacket = ("afpacket" == os.Args[1])
	}
	if lispUseAFpacket {
		lprint("Using zero-copy AF_PACKET")
	}

	//
	// Create named socket "lispets.net-itr" to punt packets to the lispers.net
	// python control-plane.
	//
	if !lispCreatePuntSocket() {
		lprint("lispCreatePuntSocket() failed")
		return (false)
	}

	//
	// Create raw socket for sending encapsulated packets.
	//
	if !lispCreateEncapSocket() {
		lprint("lispCreateEncapSocket() failed")
		return (false)
	}

	//
	// Create UDP socket for receiving IPv4 encapsulated LISP packets. For
	// IPv6 encapsulated packets use pcap.
	//
	if !lispCreateDecapSocket() {
		lprint("lispCreateDecapSocket() failed")
		return (false)
	}
	lispCreateDecapIPv6capture()

	//
	// Start stats thread.
	//
	go lispStatsThread()
	return (true)
}

//
// lispBuildHeaders
//
// Initialize pre-built headers used in lispEncapsulate().
//
func lispBuildHeaders() {

	//
	// Prebuild LISP and UDP headers. And IPv4 and IPv6 outer headers.
	//
	lispHeader = []byte{0x88, 0, 0, 0, 0, 0, 0, 0}
	lispUDPheader = []byte{0, 0, 0x10, 0xf5, 0, 8, 0, 0}
	lispIPv4header = []byte{0x45, 0, 0, 0, 0, 0, 0x40, 0, 32, 17, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0}

	//
	// IPv6 header will be 8 bytes plus an appended local source RLOC. And then
	// in lispEncapsulate(), an appended destination RLOC happens.
	//
	lispIPv6header = []byte{0x60, 0, 0, 0, 0, 0, 17, 32}
	sourceRLOC := lispGetIPv6rloc()
	if sourceRLOC == nil {
		sourceRLOC = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	}
	lprint("Using IPv6 source RLOC %s", sourceRLOC.String())
	lispIPv6header = append(lispIPv6header, sourceRLOC...)
}

//
// lispGetIPv6rloc
//
// Get the local IPv6 address on the interface with the default route.
//
func lispGetIPv6rloc() net.IP {
	interfaces, _ := net.Interfaces()

	for _, intf := range interfaces {
		if intf.Name != "eth0" {
			continue
		}
		addrs, _ := intf.Addrs()
		for _, addr := range addrs {
			a := addr.String()
			if !strings.Contains(a, ":") {
				continue
			}
			if strings.Contains(a, "fe80") {
				continue
			}
			a = strings.Split(a, "/")[0]
			return (net.ParseIP(a))
		}
	}
	return (nil)
}

//
// lispXTRshutdown
//
// Undo what was initialized in lispXTRstartup().
//
func lispXTRshutdown() {

	//
	// Close sockets.
	//
	lispIPCsocket.Close()
	lispPuntSocket.Close()

	lprint("lispers.net LISP shutting down")
}

//
// lispCreateEncapSocket
//
// Create raw sockets for IPv4 and IPv6 to be used after a LISP, UDP, and
// outer headers are prepended.
//
func lispCreateEncapSocket() bool {

	//
	// Create IPv4 raw socket.
	//
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW,
		syscall.IPPROTO_RAW)
	if err != nil {
		lprint("syscall.Socket() for IPv4 encap socket failed: %s", err)
		return (false)
	}
	lispEncapSocket[0] = s

	//
	// Create IPv6 raw socket.
	//
	s, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW,
		syscall.IPPROTO_RAW)
	if err != nil {
		lprint("syscall.Socket() for IPv6 encap socket failed: %s", err)
		return (false)
	}
	lispEncapSocket[1] = s
	return (true)
}

//
// lispCreateDecapNatCapture
//
// Since the kernel will not pass UDP packets with checksum 0 through the
// raw sockets interface, we must pcap them in the ETR.
//
func lispCreateDecapIPv6capture() {
	pfilter := "ether proto 0x86dd and dst net 0::/0 and dst port 4341"

	lprint("Capturing LISP packets with IPv6 RLOCs for '%s'", pfilter)
	go lispETRipv6Thread(pfilter)
}

//
// lispCreateDecapNatCapture
//
// Packet capture when an RTR encapsulates packets from port 4341 to the
// ephemeral port 'lisp-etr-nat-port' passed in from the lispers.net control-
// plane. We cannot open a socket because the control-plane needs it for
// Info-Replies.
//
func lispCreateDecapNatCapture() {
	pfilter := fmt.Sprintf("(src port 4341 and dst port %d)",
		lispETRnatPort)

	lprint("Capturing nat-traversal packets for '%s'", pfilter)
	go lispETRnatThread(pfilter)
}

//
// lispCreateDecapSocket
//
// Create UDP datagram socket and bind to well-known LISP port 4341.
//
func lispCreateDecapSocket() bool {
	udpAddr, err := net.ResolveUDPAddr("udp4", ":4341")
	if err != nil {
		lprint("net.ResolveUDPAddr() failed: %s", err)
		return (false)
	}

	udpSocket, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		lprint("net.ListenUDP() on port 4341 failed: %s\n", err)
		return (false)
	}
	lispDecapSocket = udpSocket

	//
	// Start ETR thread.
	//
	go lispETRthread()
	return (true)
}

//
// lispStartITRdataPlane
//
// Setup ITR capture filters and start thread for each interface we are
// capturing on.
//
func lispStartITRdataPlane() {

	//
	// Setup filters based on database-mappings provided by the lispers.net
	// control-plane.
	//
	pfilter := "(ether proto 0x0800 or 0x86dd) and (src net "
	for _, source := range lispDB {
		pfilter = pfilter + source.eidPrefix.lispPrintAddress(false) +
			" or "
	}
	pfilter = pfilter[0:len(pfilter)-4] + ")"

	//
	// Start thread for new interfaces added to lispNterfaces.
	//
	for device := range lispNterfaces {
		go lispITRthread(device, pfilter)
	}
}

//
// lispCreateAFpacketSocket
//
// Use AF_PACKET interface. Requires the caller to select an interface and
// a pcap filter string.
//
func lispCreateAFpacketSocket(device string, pfilter string) *afpacket.TPacket {

	tp, err := afpacket.NewTPacket(afpacket.OptInterface(device),
		afpacket.TPacketVersion1)
	if err != nil {
		lprint("afpacket.NewTPacket() failed %s\n", err)
		return (nil)
	}

	instructions, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet,
		1600, pfilter)
	if err != nil {
		lprint("pcap.CompileBPFFilter() failed %s\n", err)
		return (nil)
	}

	//
	// The pcap and bpf modules don't connect with the same types. Others
	// have suggested this ugly hack. Types pcap.BPFInstruction is the
	// same format as bpf.RawInstruction. Need to cast to get this to
	// compile.
	//
	rawInstructions := *(*[]bpf.RawInstruction)(unsafe.Pointer(&instructions))

	if tp.SetBPF(rawInstructions) != nil {
		lprint("tp.SetBPF() failed %s\n", err)
		return (nil)
	}
	return (tp)
}

//
// lispITRthread
//
// Run thread to packet capture packets and try to encapsulate them.
//
func lispITRthread(device string, pfilter string) {
	configChange := lispConfigChange

	if lispUseAFpacket == false {
		lprint("ITR capturing packets on %s for '%s'", bold(device), pfilter)

		handle, _ := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
		handle.SetBPFFilter(pfilter)

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for goPacket := range packetSource.Packets() {
			packet := goPacket.Data()[14:]
			lispITRdataPlane(packet, device)
			if configChange != lispConfigChange {
				handle.Close()
				break
			}
		}

	} else {

		tp := lispCreateAFpacketSocket(device, pfilter)
		if tp == nil {
			return
		}

		lprint("ITR afPacket capturing on %s for '%s'", bold(device), pfilter)

		for {
			afPacket, _, _ := tp.ZeroCopyReadPacketData()
			if afPacket == nil {
				continue
			}
			packet := afPacket[14:]

			lispITRdataPlane(packet, device)

			if configChange != lispConfigChange {
				tp.Close()
				break
			}
		}
	}

	lprint("Exit ITR thread for %s", device)
}

//
// lispITRdataPlane
//
// This function receives packet natively from the PF_RING, does a map-cache
// lookup on the destination address and encapsulates to RLOC.
//
// The encapsulation format after the outer header is:
//
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    / |       Source Port = xxxx      |       Dest Port = 4341        |
//  UDP +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    \ |           UDP Length          |        UDP Checksum           |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  L   |N|L|E|V|I|P|K|K|            Nonce/Map-Version                  |
//  I \ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  S / |                 Instance ID/Locator-Status-Bits               |
//  P   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
func lispITRdataPlane(packet []byte, inputDevice string) {
	var s, d []byte
	var iid int
	var ttl byte
	var source lispAddress
	var dest lispAddress

	if lispDataPlaneLogging {
		lispLogPacket("Received on "+bold(inputDevice), packet, false)
	}

	ipv4 := (packet[0]&0xf0 == 0x40)
	ipv6 := (packet[0]&0xf0 == 0x60)

	if ipv4 {
		if len(packet) < 20 {
			dprint("IPv4 invalid packet length, discard packet")
			return
		}
		if !lispIPchecksum(packet[0:20], true) {
			lispCount(nil, "checksum-error", packet)
			dprint("IPv4 header checksum failed, discard packet")
			return
		}
		err := lispTTLcheck(&packet[8])
		if err {
			return
		}
		lispIPchecksum(packet[0:20], false)
		s = packet[12:16]
		d = packet[16:20]
		ttl = packet[8]
	} else if ipv6 {
		if len(packet) < 40 {
			dprint("IPv6 invalid packet length, discard packet")
			return
		}
		err := lispTTLcheck(&packet[7])
		if err {
			return
		}
		s = packet[8:24]
		d = packet[24:40]
		ttl = packet[7]
	} else {
		dprint("Received non-IP packet, discard packet")
		return
	}

	//
	// Get instance-ID to use from lispInterface.
	//
	lispInt, ok := lispNterfaces[inputDevice]
	if ok {
		iid = lispInt.instanceID
	} else {
		iid = 0
	}

	//
	// Do a lispDB lookup on the source to see if its an EID.
	//
	source.lispMakeAddress(iid, s)
	err := lispGetDatabase(source)
	if err {
		dprint("Source %s is not an EID, discard packet",
			source.lispPrintAddress(true))
		return
	}
	dest.lispMakeAddress(iid, d)

	if lispDataPlaneLogging {
		dprint("Packet EIDs %s -> %s", green(source.lispPrintAddress(true)),
			green(dest.lispPrintAddress(true)))
	}

	//
	// Do self check. ICMP typically sends packet to itself. We don't need LISP
	// encap to itself.
	//
	if source.address.Equal(dest.address) {
		dprint("Discard packet addressed to self")
		return
	}

	//
	// Do destination map-cache lookup.
	//
	rloc, hash, rles := lispMapCacheLookup(source, dest)
	if rloc == nil && len(rles) == 0 {
		lispPuntPacket(inputDevice, source, dest)
		return
	}

	//
	// Increment packet counters, prepend outer headers, and send. Check to
	// see if we are replicating to a set of RLOCs or sending to just one. For
	// multicast replication, since append()s are done in lispEncapsulate()
	// the packet will be copied so a unique packet will be transmitted.
	//
	for _, rle := range rles {
		lispCount(&rle.stats, "", packet)
		lispEncapsulate("Replicate", packet, dest.instanceID, &rle, ttl,
			hash)
	}
	if rloc != nil {
		lispCount(&rloc.stats, "", packet)
		lispEncapsulate("Encapsulate", packet, dest.instanceID, rloc, ttl,
			hash)
	}
}

//
// lispEncrypt
//
// Encrypt byte array supplied in function call. Return empty array if any
// errors occurred in crypto libraries.
//
func lispEncrypt(plaintext []byte, lisp []byte, rloc *lispRloc) (
	ciphertext []byte) {

	key := rloc.keys[rloc.useKeyID]

	//
	// Increment IV stored in lispKeys. aes.Seal() wants a 12-byte nonce.
	//
	iv := binary.BigEndian.Uint64(key.iv[4:12]) + 1
	binary.BigEndian.PutUint64(key.iv[4:12], iv)

	//
	// Encrypt.
	//
	ciphertext = key.cryptoAlg.Seal(nil, key.iv, plaintext, nil)

	//
	// Set key-id in LISP header.
	//
	flags := int(lisp[0])
	lisp[0] = byte(flags | rloc.useKeyID)

	//
	// Prepend IV to packet.
	//
	ciphertext = append(key.iv, ciphertext...)

	//
	// Compute ICV over the LISP header, IV, and ciphertext. Then append the
	// ICV value to the ciphertext.
	//
	icvData := append(lisp, ciphertext...)

	//
	// Run hash.
	//
	key.hashAlg.Reset()
	key.hashAlg.Write(icvData)
	icv := key.hashAlg.Sum(nil)
	icv = icv[0:20]
	return (append(ciphertext, icv...))
}

//
// lispDecrypt
//
// First check ICV and then decrypt the packet.
//
func lispDecrypt(packet []byte, keyID int, srloc string) (plaintext []byte) {

	//
	// Are we doing crypto?
	//
	rloc := lispDecapKeys[srloc]
	if rloc == nil {
		s := strings.Split(srloc, ":")[0]
		rloc = lispDecapKeys[s]
		if rloc == nil {
			dprint("No keys found for source RLOC %s", srloc)
			lispCount(nil, "no-decrypt-key", packet)
			return (nil)
		}
		srloc = s
	}
	key := rloc.keys[rloc.useKeyID]
	if key == nil {
		lispCount(nil, "no-decrypt-key", packet)
		dprint("Key-id %d not found for source RLOC %s", keyID, srloc)
		return (nil)
	}

	//
	// Compute ICV over the LISP header, IV, and ciphertext that is included
	// in the 'ciphertext' []byte slice.
	//
	icvLen := 20
	packetICV := packet[len(packet)-icvLen:]
	packet = packet[0 : len(packet)-icvLen]
	key.hashAlg.Reset()
	key.hashAlg.Write(packet)
	computedICV := key.hashAlg.Sum(nil)
	computedICV = computedICV[0:20]
	if !hmac.Equal(packetICV, computedICV) {
		lispCount(nil, "ICV-error", packet)
		dprint("ICV failed from %s for key-id %d icv-key %s", srloc, keyID,
			key.icvKey)
		return (nil)
	}

	//
	// Decrypt. Skip past LISP header and IV.
	//
	lisp := packet[0:8]
	iv := packet[8 : 8+12]
	packet = packet[20:]
	plaintext, err := key.cryptoAlg.Open(nil, iv, packet, nil)
	if err != nil {
		lispCount(nil, "ICV-error", packet)
		dprint("Decrypt failed from %s for key-id %d crypto-key %s", srloc,
			keyID, key.cryptoKey)
		return (nil)
	}
	return (append(lisp, plaintext...))
}

//
// lispEncapsulate
//
// This function is called from either lispITRdataPlane() or lisp_etr_
// data_plane(). If the former, a packet is received natively from an EID
// source and is encapsulated to the RLOC that maps from the destination EID.
// If the later, the packet is decapsulated, and if the destination is found
// in the map-cache, it is re-encapsulated (RTR function). Otherwise, it is
// sent to the kernel to natively forward.
//
func lispEncapsulate(log string, packet []byte, iid int, rloc *lispRloc,
	ttl byte, hash int) {
	var sa4 syscall.SockaddrInet4
	var sa6 syscall.SockaddrInet6
	var outer []byte
	var err error

	//
	// Store instance-ID and nonce in LISP header.
	//
	nonce := rand.Uint32() & 0xffffff
	lisp := lispHeader
	lisp[1] = byte((nonce >> 16) & 0xff)
	lisp[2] = byte((nonce >> 8) & 0xff)
	lisp[3] = byte(nonce & 0xff)
	lisp[4] = byte((iid >> 16) & 0xff)
	lisp[5] = byte((iid >> 8) & 0xff)
	lisp[6] = byte(iid & 0xff)

	//
	// Encrypt the inner header and payload if a keys are stored in the RLOC
	// entry.
	//
	if rloc.useKeyID == 0 {
		flags := int(lisp[0])
		lisp[0] = byte(flags & 0xfc)
	} else {
		packet = lispEncrypt(packet, lisp, rloc)
	}

	//
	// Prepend LISP header.
	//
	packet = append(lisp, packet...)

	//
	// Store values in UDP header. Source port uses 5-tuple hash unless
	// lisp-crypto is running and we negotiated keys with the RLOC, then use
	// same port as RLOC-probes.
	//
	udp := lispUDPheader
	if rloc.encapPort == 4341 {
		if rloc.useKeyID == 0 {
			udp[0] = byte((hash >> 8) | 0xf0)
			udp[1] = byte(hash & 0xff)
		} else {
			udp[0] = byte(lispITRcryptoPort >> 8)
			udp[1] = byte(lispITRcryptoPort & 0xff)
		}
	} else {
		udp[0] = byte(0x10)
		udp[1] = byte(0xf5)
	}
	udp[2] = byte(rloc.encapPort >> 8)
	udp[3] = byte(rloc.encapPort & 0xff)
	udpLength := len(packet) + 8
	udp[4] = byte(udpLength >> 8)
	udp[5] = byte(udpLength & 0xff)
	packet = append(udp, packet...)

	//
	// Prepend outer header. Since we are sending on a raw socket, kernel
	// fills in source RLOC address and IPv4 checksum.
	//
	if rloc.rloc.lispIsIpv4() {
		outer = lispIPv4header
		ipLength := udpLength + 20
		outer[2] = byte(ipLength >> 8)
		outer[3] = byte(ipLength & 0xff)
		outer[8] = ttl
		outer = append(outer[0:16], rloc.rloc.address...)
		packet = append(outer, packet...)

		if !lispIPchecksum(packet[0:20], false) {
			dprint("Could not calculate IPv4 header checksum")
			return
		}

		//
		// Do string manipulation only when data-plane logging enabled.
		//
		if lispDataPlaneLogging {
			dprint("%s to IPv4 RLOC %s", log, red(fmt.Sprintf("%s:%d",
				rloc.rloc.lispPrintAddress(false), rloc.encapPort)))

			if rloc.useKeyID == 0 {
				lispLogPacket(bold("Encap"), packet, true)
			} else {
				lispLogPacket(bold("Encrypt/Encap"), packet, true)
			}
		}

		//
		// Send on raw socket.
		//
		copy(sa4.Addr[:], rloc.rloc.address)
		sa4.Port = rloc.encapPort
		err = syscall.Sendto(lispEncapSocket[0], packet, 0, &sa4)

	} else if rloc.rloc.lispIsIpv6() {
		outer = lispIPv6header
		outer[4] = byte(udpLength >> 8)
		outer[5] = byte(udpLength & 0xff)
		outer[7] = ttl
		outer = append(outer, rloc.rloc.address...)
		packet = append(outer, packet...)

		//
		// Do string manipulation only when data-plane logging enabled.
		//
		if lispDataPlaneLogging {
			dprint("%s to IPv6 RLOC %s", log, red(fmt.Sprintf("%s:%d",
				rloc.rloc.lispPrintAddress(false), rloc.encapPort)))

			if rloc.useKeyID == 0 {
				lispLogPacket(bold("Encap"), packet, true)
			} else {
				lispLogPacket(bold("Encrypt/Encap"), packet, true)
			}
		}

		//
		// Send on raw socket.
		//
		copy(sa6.Addr[:], rloc.rloc.address)
		sa6.Port = rloc.encapPort
		err = syscall.Sendto(lispEncapSocket[1], packet, 0, &sa6)
	} else {
		return
	}

	//
	// Did we get a send error?
	//
	if err != nil {
		dprint("syscall.Sendto() to RLOC %s failed: %s",
			red(rloc.rloc.lispPrintAddress(false)), err)
	}
}

//
// lispMapCacheLookup
//
// Do a LISP map-cache lookup on the destination EID.
//
func lispMapCacheLookup(source lispAddress, dest lispAddress) (*lispRloc,
	int, []lispRloc) {

	mc := lispLMLlockup(dest)

	//
	// Map-cache entry not found.
	//
	if mc == nil {
		dprint("Map-cache lookup %s for EID %s, punt packet", bold("miss"),
			dest.lispPrintAddress(true))
		return nil, 0, []lispRloc{}
	}

	dprint("Map-cache lookup %s %s for EID %s", bold("found"),
		green(mc.eidPrefix.lispPrintAddress(true)),
		dest.lispPrintAddress(true))

	//
	// Map-cache entry has an rle-set.
	//
	if len(mc.rleSet) != 0 {
		return nil, 0, mc.rleSet
	}

	//
	// Map-cache entry has empty rloc-set.
	//
	rlocSetLen := len(mc.rlocSet)
	if rlocSetLen == 0 {
		dprint("Map-cache entry has empty rloc-set, punt packet")
		return nil, 0, []lispRloc{}
	}

	//
	// Get specific RLOC from rloc-set by hashing source and dest EIDs.
	//
	hash := int(source.lispHashAddress() ^ dest.lispHashAddress())
	index := hash % rlocSetLen
	return &mc.rlocSet[index], hash, []lispRloc{}
}

//
// lispETRthread
//
// Run thread to listen on port 4341 raw socket.
//
func lispETRthread() {
	var source net.IP

	if lispUseAFpacket == false {
		lprint("Listening on raw socket port 4341")

		buf := make([]byte, 8192)
		for {
			n, source, err := lispDecapSocket.ReadFromUDP(buf)
			if err != nil {
				lprint("RecvFromUDP() failed: %s", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			lispETRdataPlane(buf[0:n], source.String())
		}

	} else {

		device := "eth1"
		addr, _ := lispGetLocalAddress(device)
		if addr == "" {
			lprint("No RLOC address on interface %s", device)
			return
		}
		pfilter := "ether proto 0x0800 and dst net "
		pfilter += addr + "/32 and dst port 4341"

		tp := lispCreateAFpacketSocket(device, pfilter)
		if tp == nil {
			return
		}

		lprint("ETR afPacket capturing on %s for '%s'", bold(device), pfilter)

		for {
			afPacket, _, _ := tp.ZeroCopyReadPacketData()
			if afPacket == nil {
				continue
			}
			packet := afPacket[14:]

			source = packet[12:16]
			sourceRLOC := source.String() + ":"
			sourceRLOC += strconv.Itoa(int(packet[20])<<8 + int(packet[21]))
			packet = packet[28:]
			lispETRdataPlane(packet, sourceRLOC)
		}
	}
}

//
// lispETRipv6Thread
//
// Run thread to capture any LISP encapsulated packets with IPv6 RLOCs. We
// need to get packets this way since the kernel will not pass UDP packets
// with checksum 0 through a raw packet interface.
//
// Note, there is a 2-byte Linux header before the MAC header.
//
func lispETRipv6Thread(pfilter string) {
	var source net.IP

	handle, _ := pcap.OpenLive("any", 1600, true, pcap.BlockForever)
	handle.SetBPFFilter(pfilter)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for gopacket := range packetSource.Packets() {
		packet := gopacket.Data()[16:]

		source = packet[8:24]
		sourceRLOC := source.String() + ":"
		sourceRLOC += strconv.Itoa(int(packet[40])<<8 + int(packet[41]))
		packet = packet[48:]
		lispETRdataPlane(packet, sourceRLOC)
	}
}

//
// lispETRnatThread
//
// Run thread to packet capture packts to port lisp_nat_etr_port'. We have
// jump over headers so lispETRdataPlane() believes the packet starts
// at the LISP header.
//
// Note, there is a 2-byte Linux header before the MAC header.
//
func lispETRnatThread(pfilter string) {
	var source net.IP

	handle, _ := pcap.OpenLive("any", 1600, true, pcap.BlockForever)
	handle.SetBPFFilter(pfilter)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for gopacket := range packetSource.Packets() {
		packet := gopacket.Data()[16:]

		source = packet[12:16]
		sourceRLOC := source.String() + ":" + "4341"
		packet = packet[28:]
		lispETRdataPlane(packet, sourceRLOC)
	}
}

//
// lispETRdataPlane
//
// Process received LISP encapsulated packet.
//
func lispETRdataPlane(packet []byte, sourceRLOC string) {
	var inner, lisp []byte
	var source, dest lispAddress
	var socket, iid int
	var ttl byte

	//
	// Isolate LISP header and get key-id to determine if we are decrypting.
	//
	lisp = packet[0:8]
	keyID := int(lisp[0] & 0x3)
	if keyID != 0 {
		if lispDataPlaneLogging {
			lispLogPacket(bold("Decap/Decrypt ")+red(sourceRLOC), packet,
				true)
		}
		packet = lispDecrypt(packet, keyID, sourceRLOC)
		if packet == nil {
			return
		}
	} else {
		if lispDataPlaneLogging {
			lispLogPacket(bold("Decap ")+red(sourceRLOC), packet, true)
		}
	}

	//
	// Get instance-id from LISP header. Instance-ID of -1 is an encapsulated
	// control message, drop it. The lispers.net control-plane will deliver it.
	//
	if (lisp[0] & 0x08) == 0x08 {
		iid = int(lisp[4])<<16 + int(lisp[5])<<8 + int(lisp[6])
		if iid == 0xffffff {
			return
		}
	} else {
		iid = 0
	}

	//
	// Position packet to inner packet header.
	//
	inner = packet[8:]
	innerVersion := (inner[0] & 0xf0)

	//
	// Check TTL before parsing addresses.
	//
	if innerVersion == 0x40 {
		if !lispIPchecksum(inner[0:20], true) {
			lispCount(nil, "checksum-error", packet)
			dprint("IPv4 header checksum failed, discard packet")
			return
		}
		err := lispTTLcheck(&inner[8])
		if err {
			return
		}

		lispIPchecksum(inner[0:20], false)
		source.lispMakeAddress(iid, inner[12:16])
		dest.lispMakeAddress(iid, inner[16:20])
		ttl = inner[8]
		socket = 0
	} else if innerVersion == 0x60 {
		err := lispTTLcheck(&inner[7])
		if err {
			return
		}

		source.lispMakeAddress(iid, inner[8:24])
		dest.lispMakeAddress(iid, inner[24:40])
		ttl = inner[7]
		socket = 1
	} else {
		lispCount(nil, "bad-inner-version", packet)
		dprint("Invalid inner IP header version 0x%x", innerVersion)
		return
	}

	//
	// Do a lispDB lookup on the destination to see if its an EID. Don't
	// do this for a destination multicast address or we are an RTR node.
	//
	if !lispRTR && !dest.lispIsMulticast() {
		err := lispGetDatabase(dest)
		if err {
			dprint("Destination %s is not a configured EID",
				dest.lispPrintAddress(true))
			return
		}
		lispSend(socket, inner, source, dest)
		return
	}

	//
	// Do the following only if configured as an RTR.
	//
	if !lispRTR {
		return
	}

	dprint("Packet EIDs %s -> %s, RTR processing",
		green(source.lispPrintAddress(true)),
		green(dest.lispPrintAddress(true)))

	//
	// We are now acting as an RTR, do destination map-cache lookup.
	//
	rloc, hash, rles := lispMapCacheLookup(source, dest)
	if rloc == nil && len(rles) == 0 {
		lispPuntPacket("?", source, dest)
		return
	}

	lispCount(nil, "good-packets", inner)

	//
	// Increment packet counters, prepend outer headers, and send. Check to
	// see if we are replicating to a set of RLOCs or sending to just one. For
	// multicast replication, since append()s are done in lispEncapsulate()
	// the packet will be copied so a unique packet will be transmitted.
	//
	for _, rle := range rles {
		lispCount(&rle.stats, "", packet)
		lispEncapsulate("Replicate", inner, dest.instanceID, &rle, ttl, hash)
	}
	if rloc != nil {
		lispCount(&rloc.stats, "", packet)
		lispEncapsulate("Encapsulate", inner, dest.instanceID, rloc, ttl,
			hash)
	}
}

//
// lispSend
//
// Send packet after its been decapsulated.
//
func lispSend(socket int, inner []byte, s lispAddress, d lispAddress) {
	var sa4 syscall.SockaddrInet4
	var sa6 syscall.SockaddrInet6
	var source string
	var dest string

	if lispDataPlaneLogging {
		source = green(s.lispPrintAddress(true))
		dest = green(d.lispPrintAddress(true))
		dprint("Forward packet %s -> %s", source, dest)
	}

	sendSocket := lispEncapSocket[socket]

	if socket == 0 {
		copy(sa4.Addr[:], d.address)
		sa4.Port = 0
		err := syscall.Sendto(sendSocket, inner, 0, &sa4)
		if err != nil {
			dprint("syscall.Sendto() to IPv4 EID %s failed: %s", dest, err)
			return
		}
	} else {
		copy(sa6.Addr[:], d.address)
		sa6.Port = 0
		err := syscall.Sendto(sendSocket, inner, 0, &sa6)
		if err != nil {
			dprint("syscall.Sendto() to IPv6 EID %s failed: %s", dest, err)
			return
		}
	}
	lispCount(nil, "good-packets", inner)
	return
}

//
// lispTTLcheck
//
// Check the received packet still has enough TTL to forward packet.
//
func lispTTLcheck(ttl *byte) bool {
	if *ttl == 0 {
		dprint("TTL arrived as 0, discard packet")
		return (true)
	}
	*ttl = *ttl - 1
	if *ttl == 0 {
		dprint("TTL decremented to 0, discard packet")
		return (true)
	}
	return (false)
}

//
// lispGetDatabase
//
// See if address matches a database-entry, if so, its an EID. If it is not
// return err true.
//
func lispGetDatabase(address lispAddress) bool {
	for _, ldb := range lispDB {
		if ldb.eidPrefix.lispMoreSpecific(address) {
			return (false)
		}
	}
	return (true)
}

//
// lispIPchecksum
//
// Input to this function is 20-bytes in packed form. Calculate IP header
// checksum and place in byte 10 and byte 11 of header when we are computing
// a checksum for an outer header being sent. For checking a received packet,
// the checksum in the header must be non-zero.
//
func lispIPchecksum(data []byte, checking bool) bool {
	var checksum, packetChecksum int

	length := len(data)
	if length < 20 {
		lprint("IPv4 packet too short, length %s", length)
		return (false)
	}

	//
	// If checking the checksum, the header checksum field must be non-zero.
	// If computing the checksum the header checksum field must be zero.
	//
	packetChecksum = int(data[10])<<8 + int(data[11])
	if checking && packetChecksum == 0 {
		lprint("IPv4 header checksum field is 0, discard packet")
		return (false)
	}
	if !checking && packetChecksum != 0 {
		lprint("IPv4 checksum not computed when packet checksum is non-zero")
		return (false)
	}
	checksum = 0
	data[10] = 0
	data[11] = 0

	//
	// Go 2-bytes at a time so we only have to fold carry-over once.
	//
	for i := 0; i < length; i += 2 {
		checksum += int(data[i])<<8 + int(data[i+1])
	}

	//
	// Add in carry. And take 1's complement.
	//
	carry := checksum >> 16
	checksum = checksum & 0xffff
	checksum += carry
	checksum = ^checksum & 0xffff

	//
	// Pack in 2-byte buffer and insert at bytes 10 and 11.
	//
	if checking {
		return (packetChecksum == checksum)
	}
	data[10] = byte(checksum >> 8)
	data[11] = byte(checksum & 0xff)
	return (true)
}

//-----------------------------------------------------------------------------
