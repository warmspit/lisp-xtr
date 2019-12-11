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
// lisp.go
//
// This file contains function and type definitions used by xtr.go and ipc.go.
//
// This is a external data-plane from the lispers.net control-plane perspective
// and must be run with "lisp xtr-parameters" sub-command "ipc-data-plane =
// yes".
//
// ---------------------------------------------------------------------------

package main

import "fmt"
import "bufio"
import "os"
import "os/exec"
import "strings"
import "strconv"
import "time"
import "net"
import "hash"
import "math/rand"
import "encoding/binary"
import "crypto/aes"
import "crypto/cipher"
import "crypto/sha256"
import "crypto/hmac"
import "encoding/hex"

//
// ---------- Variable Definitions ----------
//
var lispDebugLogging = true
var lispDataPlaneLogging = false

//
// ---------- Constants Definitions ----------
//
const lispDataPort = 4341
const lispCtrlPort = 4342
const lispL2DataPort = 8472
const lispVxlanDataPort = 4789
const lispVxlanGpePort = 4790

//
// ---------- Type Definitions ----------
//
type lispAddress struct {
	instanceID    int
	maskLen       int
	address       net.IP
	maskAddress   net.IPMask
	addressString string
}

//
// lispPrintAddress
//
// Return string with address. And optionally prepend "[<iid>]"
//
func (a *lispAddress) lispPrintAddress(withIID bool) string {
	if a.addressString == "" {
		a.addressString = a.address.String()
	}

	if withIID {
		iid := a.instanceID
		if iid == 0xffffff {
			iid = -1
		}
		return (fmt.Sprintf("[%d]%s", iid, a.addressString))
	}
	return (a.addressString)
}

//
// lispStoreAddress
//
// Store and instance-ID and string representation of an IPv4 or IPv6 address
// and store in lispAddress format.
//
func (a *lispAddress) lispStoreAddress(iid int, addr string) bool {
	var address string

	//
	// Is this address string an address or a prefix?
	//
	if strings.Contains(addr, "/") {
		split := strings.Split(addr, "/")
		address = split[0]
		a.maskLen, _ = strconv.Atoi(split[1])
	} else {
		address = addr
		a.maskLen = -1
	}
	a.instanceID = iid

	//
	// Parse address string. ParseIP() will put IPv4 addresses in a 16-byte
	// array. We don't want that because address []byte length will determine
	// address family.
	//
	a.address = net.ParseIP(address)
	if strings.Contains(addr, ".") {
		a.address = a.address[12:16]
	}

	//
	// Set mask-length and mask address.
	//
	if a.maskLen == -1 {
		a.maskLen = len(a.address) * 8
	}
	a.maskAddress = net.CIDRMask(a.maskLen, len(a.address)*8)

	//
	// Store string for printing.
	//
	a.addressString = addr
	return (true)
}

//
// lispIsIpv4
//
// Return true if lispAddress is IPv4.
//
func (a *lispAddress) lispIsIpv4() bool {
	return (len(a.address) == 4)
}

//
// lispIsIpv6
//
// Return true if lispAddress is IPv6.
//
func (a *lispAddress) lispIsIpv6() bool {
	return (len(a.address) == 16)
}

//
// lispIsMulticast
//
// Return true if lispAddress is an IPv4 or IPv6 multicast group address.
//
func (a *lispAddress) lispIsMulticast() bool {
	if a.lispIsIpv4() {
		return (int(a.address[0]) >= 224 && int(a.address[0]) < 240)
	}
	if a.lispIsIpv6() {
		return (a.address[0] == 0xff)
	}
	return (false)
}

//
// lispMakeAddress
//
// Store and instance-ID and byte representation of an IPv4 or IPv6 address
// and store in lispAddress format. Note that lispAddress.addressString
// is created when it is needed (in lispAddress.lispPrintAddress()).
//
func (a *lispAddress) lispMakeAddress(iid int, addr []byte) {
	a.instanceID = iid
	a.address = addr
	a.maskLen = len(a.address) * 8
	a.maskAddress = net.CIDRMask(a.maskLen, len(a.address)*8)
}

//
// lispExactMatch
//
// Compare two addresses and return true if they match.
//
func (a *lispAddress) lispExactMatch(addr lispAddress) bool {
	if len(a.address) != len(addr.address) {
		return (false)
	}
	if a.maskLen != addr.maskLen {
		return (false)
	}
	if a.instanceID != addr.instanceID {
		return (false)
	}
	if a.address.Equal(addr.address) == false {
		return (false)
	}
	return (true)
}

//
// lispMoreSpecific
//
// Return true if the supplied address is more specific than the method
// address. If the mask-lengths are the same, a true is returned.
//
func (a *lispAddress) lispMoreSpecific(addr lispAddress) bool {
	if len(a.address) != len(addr.address) {
		return (false)
	}
	if a.instanceID != addr.instanceID {
		return (false)
	}
	if a.maskLen > addr.maskLen {
		return (false)
	}
	for i := 0; i < len(a.address); i++ {
		if a.maskAddress[i] == 0 {
			break
		}
		if (a.address[i] & a.maskAddress[i]) !=
			(addr.address[i] & a.maskAddress[i]) {
			return (false)
		}
	}
	return (true)
}

//
// lispHashAddress
//
// Hash address to aid in selecting a source UDP port.
//
func (a *lispAddress) lispHashAddress() uint16 {
	var hash uint = 0

	for i := 0; i < len(a.address); i++ {
		hash = hash ^ uint(a.address[i])
	}

	//
	// Fold result into a short.
	//
	return (uint16(hash>>16) ^ uint16(hash&0xffff))
}

type lispDatabase struct {
	eidPrefix lispAddress
}
type lispInterface struct {
	instanceID int
}
type lispMapCache struct {
	nextMc    *lispMapCache
	eidPrefix lispAddress
	rlocSet   []lispRloc
	rleSet    []lispRloc
}
type lispRloc struct {
	rloc      lispAddress
	encapPort int
	stats     lispStats
	keys      [4]*lispKeys
	useKeyID  int
}
type lispKeys struct {
	cryptoKey string
	icvKey    string
	iv        []byte
	cryptoAlg cipher.AEAD
	hashAlg   hash.Hash
}
type lispStats struct {
	packets    uint64
	bytes      uint64
	lastPacket time.Time
}

//
// lispCount
//
// Increment stats counters. Either do it for an RLOC/RLE entry or for the
// lispDecapStats map. Argument 'key-name' needs to be set if stats is nil.
//
func lispCount(stats *lispStats, keyName string, packet []byte) {
	if stats == nil {
		s, ok := lispDecapStats[keyName]
		if !ok {
			s = new(lispStats)
			lispDecapStats[keyName] = s
		}
		s.packets++
		s.bytes += uint64(len(packet))
		s.lastPacket = time.Now()
	} else {
		stats.packets++
		stats.bytes += uint64(len(packet))
		stats.lastPacket = time.Now()
	}
}

//
// lispFindRLOC
//
// Find RLOC entry in map-cache entry based on supplied RLOC address.
//
func (mc *lispMapCache) lispFindRLOC(rlocAddr lispAddress) *lispRloc {
	for _, rloc := range mc.rlocSet {
		if rlocAddr.lispExactMatch(rloc.rloc) {
			return (&rloc)
		}
	}
	return (nil)
}

//
// lprint
//
// Print control-plane debug logging output when configured.
//
func lprint(format string, args ...interface{}) {
	if !lispDebugLogging {
		return
	}

	ts := time.Now()
	ms := ts.Nanosecond() / 1000000
	ds := fmt.Sprintf("%02d/%02d/%02d %02d:%02d:%02d.%03d", ts.Month(),
		ts.Day(), ts.Year(), ts.Hour(), ts.Minute(), ts.Second(), ms)
	f := ds + ": xtr: " + format + "\n"
	fmt.Printf(f, args...)
}

//
// dprint
//
// Print data-plane debug logging output when configured.
//
func dprint(format string, args ...interface{}) {
	if !lispDataPlaneLogging {
		return
	}

	ts := time.Now()
	ms := ts.Nanosecond() / 1000000
	ds := fmt.Sprintf("%02d/%02d/%02d %02d:%02d:%02d.%03d", ts.Month(),
		ts.Day(), ts.Year(), ts.Hour(), ts.Minute(), ts.Second(), ms)
	f := ds + ": xtr: " + format + "\n"
	fmt.Printf(f, args...)
}

//
// debug
//
// For temporary debug output that highlights line in boldface red.
//
func debug(format string, args ...interface{}) {
	f := red(">>>") + format + red("<<<") + "\n"
	fmt.Printf(f, args...)
}

//
// debugv
//
// For temporary debug output that shows the contents of a data structure.
// Very useful for debugging.
//
func debugv(args interface{}) {
	debug("%#v", args)
}

//
// lispCommandOutput
//
// Execute a system command and return a string with output.
//
func lispCommandOutput(command string) string {
	cmd := exec.Command(command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return ("")
	}
	output := string(out)
	return (output[0 : len(output)-1])
}

//
// lispReadFile
//
// Read entire file into a string.
//
func lispReadFile(filename string) string {
	fd, err := os.Open(filename)
	if err != nil {
		return ("")
	}
	scanner := bufio.NewScanner(fd)
	scanner.Scan()
	fd.Close()
	return (scanner.Text())
}

//
// lispWriteFile
//
// Write supplied string to supplied file.
//
func lispWriteFile(filename string, text string) {
	fd, err := os.Create(filename)
	if err != nil {
		lprint("Could not create file %s", filename)
		return
	}
	_, err = fd.WriteString(text)
	if err != nil {
		lprint("Could not write string to file %s", filename)
		return
	}
	fd.Close()
}

//
// bold
//
// Make input string boldface.
//
func bold(str string) string {
	return ("\033[1m" + str + "\033[0m")
}

//
// green
//
// Make input string green.
//
func green(str string) string {
	return ("\033[92m" + bold(str) + "\033[0m")
}

//
// red
//
// Make input string red.
//
func red(str string) string {
	return ("\033[91m" + bold(str) + "\033[0m")
}

//
// lispLogPacket
//
// Log a received data packet either native or LISP encapsulated. This function
// should be called only when lispDataPlaneLogging is true.
//
func lispLogPacket(prefixString string, packet []byte, isLisp bool) {
	var num int
	var udp, lisp []byte

	ip := true
	if packet[0] == 0x45 {
		num = 20
	} else if packet[0] == 0x60 {
		num = 40
	} else {
		num = 8
		if packet[8] == 0x45 {
			num += 20
		}
		if packet[8] == 0x60 {
			num += 40
		}
		ip = false
	}
	udp = packet[num : num+8]
	lisp = packet[num+8 : num+16]

	packetString := fmt.Sprintf("%s: ", prefixString)
	p := packet
	for i := 0; i < num; i += 4 {
		packetString += fmt.Sprintf("%02x%02x%02x%02x ", p[i], p[i+1],
			p[i+2], p[i+3])
	}

	//
	// Return for invalid packet.
	//
	if ip == false {
		dprint(packetString)
		return
	}

	if !isLisp {
		dprint(packetString)
		return
	}

	packetString += fmt.Sprintf("UDP: ")
	for i := 0; i < 8; i += 4 {
		packetString += fmt.Sprintf("%02x%02x%02x%02x ", udp[i], udp[i+1],
			udp[i+2], udp[i+3])
	}
	packetString += fmt.Sprintf("LISP: ")
	for i := 0; i < 8; i += 4 {
		packetString += fmt.Sprintf("%02x%02x%02x%02x ", lisp[i], lisp[i+1],
			lisp[i+2], lisp[i+3])
	}
	dprint(packetString)
}

//
// lispGetLocalAddress
//
// Given supplied interface, return locaal IPv4 and IPv6 addresses.
//
func lispGetLocalAddress(device string) (string, string) {
	var ipv4 string = ""
	var ipv6 string = ""

	intf, _ := net.InterfaceByName(device)
	addrs, _ := intf.Addrs()

	for _, a := range addrs {
		addr := strings.Split(a.String(), "/")[0]
		if addr == "::1" {
			continue
		}
		if strings.Contains(addr, "fe80") {
			continue
		}
		if strings.Contains(addr, "127.0.0.1") {
			continue
		}
		if strings.Contains(addr, ":") {
			ipv6 = addr
		}
		if strings.Count(addr, ".") == 3 {
			ipv4 = addr
		}
	}
	return ipv4, ipv6
}

//
// lispSetupKeys
//
// Store crypto and hash data structures so they are ready for encryption and
// ICV checking.
//
func (r *lispKeys) lispSetupKeys(cryptoKey string, icvKey string) {
	r.cryptoKey = cryptoKey
	r.icvKey = icvKey

	//
	// Allocate an IV used for encryption during encapsulation. AES-GCM wants
	// a 12-byte IV/nonce.
	//
	r.iv = make([]byte, 12)
	binary.BigEndian.PutUint32(r.iv[0:4], rand.Uint32())
	binary.BigEndian.PutUint64(r.iv[4:12], rand.Uint64())

	ekey, err := hex.DecodeString(cryptoKey)
	if err != nil {
		lprint("hex.DecodeString() failed for crypto-key, err %s", err)
		return
	}
	block, err := aes.NewCipher(ekey)
	if err != nil {
		lprint("aes.NewCipher() failed, err %s", err)
		return
	}
	r.cryptoAlg, err = cipher.NewGCM(block)
	if err != nil {
		lprint("cipher.NewGCM() failed, err %s", err)
		return
	}
	ikey, err := hex.DecodeString(icvKey)
	if err != nil {
		lprint("hex.DecodeString() failed for icv-key, err %s", err)
		return
	}
	r.hashAlg = hmac.New(sha256.New, ikey)
	lprint("Setup new keys")
	return
}

//-----------------------------------------------------------------------------
