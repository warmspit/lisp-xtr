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
// ipc.go
//
// The functions contain in this file are used to interface with the
// lispers.net control-plane.
//
// This is a external data-plane from the lispers.net control-plane perspective
// and must be run with "lisp xtr-parameters" sub-command "ipc-data-plane =
// yes".
//
// ---------------------------------------------------------------------------

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

const lispersDir = "./"

//
// 200ms rate-limiter in units of nanaoseconds.
//
const lispRateLimiter = 200000000

//
// Sockets used for control-plane IPC.
//
var lispIPCsocket *net.UnixConn
var lispPuntSocket *net.UnixConn
var lispLastPunt time.Time
var lispConfigChange int
var lispShowTimer time.Time

//
// Data structures for running the data-plane.
//
var lispDB []lispDatabase
var lispNterfaces map[string]lispInterface
var lispITRcryptoPort int
var lispETRnatPort int
var lispDecapKeys map[string]*lispRloc
var lispDecapStats map[string]*lispStats

type entireMapCache struct {
	Entries []struct {
		EidPrefix  string `json:"eid-prefix"`
		InstanceID string `json:"instance-id"`
		Opcode     string `json:"opcode"`
		Rlocs      []struct {
			Port     string `json:"port"`
			Priority string `json:"priority"`
			Rloc     string `json:"rloc"`
			Weight   string `json:"weight"`
		} `json:"rlocs"`
		Type string `json:"type"`
	} `json:"entries"`
	Type string `json:"type"`
}

type mapCache struct {
	EidPrefix  string `json:"eid-prefix"`
	InstanceID string `json:"instance-id"`
	Opcode     string `json:"opcode"`
	Rlocs      []struct {
		Port     string `json:"port"`
		Priority string `json:"priority"`
		Rloc     string `json:"rloc"`
		Weight   string `json:"weight"`
	} `json:"rlocs"`
	Type string `json:"type"`
}

type databaseMappings struct {
	DatabaseMappings []struct {
		EidPrefix  string `json:"eid-prefix"`
		InstanceID string `json:"instance-id"`
	} `json:"database-mappings"`
	Type string `json:"type"`
}

//
// lispIPCmessageProcessing
//
// Listen on socket "lisp-ipc-data-plane" for messages from the lispers.net
// python control-plane.
//
func lispIPCmessageProcessing() {
	var lispNterface lispInterface
	var lispDatabaseEntry lispDatabase
	var eid string
	var jdata map[string]interface{}
	var sa net.UnixAddr

	type lispIPCrawMsg struct {
		Type    string
		Message json.RawMessage
	}
	//
	// If named socket file exists, remove it. Then open the socket.
	//#>>> n# <<< invalid command

	sa.Name = lispersDir + "lisp-ipc-data-plane"
	sa.Net = "unixgram"
	_, err := os.Stat(sa.Name)
	if err == nil {
		os.Remove(sa.Name)
	}
	socket, err := net.ListenUnixgram("unixgram", &sa)
	if err != nil {
		lprint("net.ListenUnixgram() failed: %s", err)
		return
	}
	lispIPCsocket = socket

	//
	// Allocate lispDecapKeys map.
	//
	lispDecapKeys = make(map[string]*lispRloc)

	buf := make([]byte, 8192)
	for {
		time.Sleep(100 * time.Millisecond)

		// db timestamp
		timeIn := time.Now()

		n, err := socket.Read(buf[:])
		if err != nil {
			lprint("socket.Read() failed: %s", err)
			continue
		}

		lprint("Received %s: '%s'", bold("IPC"), buf[0:n])

		var targetIPC interface{}
		var lispIPCrawMsgs []lispIPCrawMsg

		// assume we may have packed IPC messages
		// not sure if lisp does this or not
		err = json.Unmarshal(buf, &lispIPCrawMsgs)
		if err != nil {
			lprint("error unmarshaling json in ipc loop %v %v", err, string(buf))
		}

		for _, rawMsg := range lispIPCrawMsgs {

			switch rawMsg.Type {

			case "entire-map-cache":
				targetIPC = new(databaseMappings)

			case "database-mappings":
				targetIPC = new(databaseMappings)
			case "entries":
				targetIPC = new(entireMapCache)
			case "rlocs":
				targetIPC = new(mapCache)
			default:
				lprint("unkown IPC type %v", rawMsg)
			}
			err := json.Unmarshal(rawMsg.Message, targetIPC)
			if err != nil {
				lprint("error unmarshaling IPC message %v", targetIPC)
			}
			lprint("IPC = %v")
		}

		jdata = make(map[string]interface{}, 0)
		err = json.Unmarshal(buf[0:n], &jdata)
		if err != nil {
			lprint("json.Unmarshall() failed: %s", err)
			continue
		}
		value, ok := jdata["type"]
		if !ok {
			lprint("JSON 'type' not found")
			continue
		}

		//
		// Process each JSON type.
		//
		if value == "entire-map-cache" {
			entries := jdata["entries"].([]interface{})
			if len(entries) == 0 {
				lmlClearHashTable()
			}
			for _, jj := range entries {
				j := jj.(map[string]interface{})
				lispStoreMapCacheData(j)
			}

		} else if value == "map-cache" {
			lispStoreMapCacheData(jdata)

		} else if value == "database-mappings" {
			lispDB = make([]lispDatabase, 0)
			for _, jj := range jdata["database-mappings"].([]interface{}) {
				j := jj.(map[string]interface{})
				iid, _ := strconv.Atoi(j["instance-id"].(string))
				eid = j["eid-prefix"].(string)
				lispDatabaseEntry.eidPrefix.lispStoreAddress(iid, eid)
				lispDB = append(lispDB, lispDatabaseEntry)
			}
			if len(lispDB) != 0 && len(lispNterfaces) != 0 {
				lispConfigChange++
				lispStartITRdataPlane()
			}

		} else if value == "interfaces" {
			newInterfaces := make(map[string]lispInterface, 0)
			for _, jj := range jdata["interfaces"].([]interface{}) {
				j := jj.(map[string]interface{})
				device := j["interface"].(string)
				iid, _ := strconv.Atoi(j["instance-id"].(string))

				entry, ok := lispNterfaces[device]
				if ok {
					entry.instanceID = int(iid)
					newInterfaces[device] = entry
				} else {
					lispNterface.instanceID = int(iid)
					newInterfaces[device] = lispNterface
				}
			}
			lispNterfaces = newInterfaces
			if len(lispDB) != 0 && len(lispNterfaces) != 0 {
				lispConfigChange++
				lispStartITRdataPlane()
			}

		} else if value == "itr-crypto-port" {
			lispITRcryptoPort = int(jdata["port"].(float64))

		} else if value == "etr-nat-port" {
			oldPort := lispETRnatPort
			lispETRnatPort = int(jdata["port"].(float64))
			if lispETRnatPort != oldPort {
				lispCreateDecapNatCapture()
			}

		} else if value == "decap-keys" {
			keysSet := jdata["keys"]
			if keysSet == nil {
				continue
			}
			addr := jdata["rloc"].(string)

			rloc := new(lispRloc)
			rloc.rloc.lispStoreAddress(0, addr)
			lispStoreKeys(nil, rloc, "decrypt-key", keysSet.([]interface{}))

			//
			// If there is no port, decap will do a second lookup.
			//
			index := addr
			port, ok := jdata["port"].(string)
			if ok {
				index += ":" + port
			}
			lispDecapKeys[index] = rloc

		} else if value == "xtr-parameters" {
			lispDebugLogging = jdata["control-plane-logging"].(bool)
			lispDataPlaneLogging = jdata["data-plane-logging"].(bool)
			lispRTR = jdata["rtr"].(bool)

		} else {
			lprint("JSON '%s' not supported", value)
			continue
		}

		//
		// Display entire state. But don't do it more than every 2 seconds.
		//
		if time.Since(lispShowTimer).Seconds() >= 2 {
			lispShowTimer = time.Now()
			go func() {
				time.Sleep(2 * time.Second)
				out := lispShowState()
				lispWriteFile("./show-xtr", out)
				if lispDebugLogging {
					fmt.Printf(out)
				}
			}()
		}

		// db timestamp
		debug("processing time %v", time.Now().Sub(timeIn))
	}
}

//
// lispStoreKeys
//
// Store keys in an lispRloc in the map-cache or in the lispDecapKeys
// array. There seems to be some strange issue in the hmac and sha256
// packages where if you call the libraries with the same icv key as before,
// it will not compute a good ICV. So this function takes care of detecting
// previous state with the same keys and uses that state. When keys change,
// from the LISP control-plane, the issue does not exist.
//
func lispStoreKeys(mc *lispMapCache, rloc *lispRloc, keyName string,
	keySet []interface{}) {

	var rlocKeys [4]*lispKeys
	var keys *lispKeys

	//
	// Get RLOC keys array from possibly existing map-cache entry.
	//
	if mc != nil {
		rlocEntry := mc.lispFindRLOC(rloc.rloc)
		if rlocEntry != nil {
			rlocKeys = rlocEntry.keys
		}
	}

	for _, jj := range keySet {
		j := jj.(map[string]interface{})
		keyID, _ := strconv.Atoi(j["key-id"].(string))
		if keyID < 1 && keyID > 3 {
			continue
		}

		cryptoKey, ok := j[keyName].(string)
		if ok == false {
			continue
		}
		icvKey, ok := j["icv-key"].(string)
		if ok == false {
			continue
		}

		//
		// Check if keys are the same and if so, use the values from the
		// existing RLOC map-cache entry.
		//
		if rlocKeys[keyID] != nil &&
			rlocKeys[keyID].cryptoKey == cryptoKey &&
			rlocKeys[keyID].icvKey == icvKey {
			keys = rlocKeys[keyID]
		} else {
			keys = new(lispKeys)
			keys.lispSetupKeys(cryptoKey, icvKey)
		}
		rloc.keys[keyID] = keys
		rloc.useKeyID = keyID
	}
}

//
// lispStoreMapCacheData
//
// Store map-cache data from this JSON structure documented in lisp-ipc-data-
// plane.tx.
//
func lispStoreMapCacheData(jdata map[string]interface{}) {
	var lispMCentry *lispMapCache
	var eid lispAddress

	iid, _ := strconv.Atoi(jdata["instance-id"].(string))
	eid.lispStoreAddress(iid, jdata["eid-prefix"].(string))
	lispMCentry = new(lispMapCache)
	lispMCentry.eidPrefix = eid

	//
	// Find entry and remove it. If opcode is add, then append to array.
	// If opcode is a delete, just return.
	//
	mc := lispLMLexactLookup(eid)
	if jdata["opcode"] == "delete" {
		if mc != nil {
			lispLMLdeleteEntry(mc)
		}
		return
	}

	if jdata["opcode"] == "add" {
		rlocSet := jdata["rlocs"]
		rleSet := jdata["rles"]

		if rlocSet != nil {
			for _, jj := range rlocSet.([]interface{}) {
				j := jj.(map[string]interface{})
				rloc := new(lispRloc)
				rloc.rloc.lispStoreAddress(0, j["rloc"].(string))
				rloc.encapPort, _ = strconv.Atoi(j["port"].(string))
				keysSet := j["keys"]
				if keysSet != nil {
					lispStoreKeys(mc, rloc, "encrypt-key",
						keysSet.([]interface{}))
				}
				lispMCentry.rlocSet = append(lispMCentry.rlocSet, *rloc)
			}
		}
		if rleSet != nil {
			for _, jj := range rleSet.([]interface{}) {
				j := jj.(map[string]interface{})
				rle := new(lispRloc)
				rle.rloc.lispStoreAddress(0, j["rle"].(string))
				rle.encapPort, _ = strconv.Atoi(j["port"].(string))
				keysSet := j["keys"]
				if keysSet != nil {
					lispStoreKeys(mc, rle, "encrypt-key",
						keysSet.([]interface{}))
				}
				lispMCentry.rleSet = append(lispMCentry.rleSet, *rle)
			}
		}
		if mc != nil {
			lispLMLdeleteEntry(mc)
		}
		lispLMLaddEntry(lispMCentry)
	}
}

//
// lispShowState
//
// Show data structure state.
//
func lispShowState() string {

	//
	// Header line followed by blank line.
	//
	out := "lispers.net release " + bold(lispReadFile("./lisp-version.txt"))
	out += " running at " + lispCommandOutput("date") + "\n\n"

	//
	// xTR state section.
	//
	out += fmt.Sprintf("%s\n", bold("LISP xTR State"))
	eOrD := "disabled/"
	if lispDebugLogging {
		eOrD = "enabled/"
	}
	if lispDataPlaneLogging {
		eOrD += "enabled"
	} else {
		eOrD += "disabled"
	}
	out += fmt.Sprintf("  LISP control/data-plane logging: %s\n", eOrD)
	if lispRTR {
		out += fmt.Sprintf("  LISP RTR: enabled\n")
	} else {
		out += fmt.Sprintf("  LISP RTR: disabled\n")
	}
	out += fmt.Sprintf("  LISP ITR Crypto Port: %d\n", lispITRcryptoPort)
	out += fmt.Sprintf("  LISP ETR NAT Port: %d\n", lispETRnatPort)

	//
	// Display "lisp interfaces".
	//
	out += fmt.Sprintf("  LISP Interfaces: ")
	if len(lispNterfaces) == 0 {
		out += fmt.Sprintf(" []")
	}
	for key, value := range lispNterfaces {
		out += fmt.Sprintf("%s:[%d] ", key, value.instanceID)
	}
	out += fmt.Sprintf("\n")

	//
	// Display "lisp database-mappings".
	//
	out += fmt.Sprintf("  LISP Database Mappings: ")
	if len(lispDB) == 0 {
		out += fmt.Sprintf(" []\n")
	}
	for i, value := range lispDB {
		out += fmt.Sprintf("%s", value.eidPrefix.lispPrintAddress(true))
		if i == len(lispDB)-1 {
			out += fmt.Sprintf("\n")
		} else {
			out += fmt.Sprintf(", ")
		}
	}

	//
	// Section break. Blank line before map-cache display.
	//
	out += fmt.Sprintf("\n")

	//
	// Display map-cache.
	//
	out += fmt.Sprintf("%s\n", bold("LISP xTR Map-Cache State"))
	for mc := lispLMLwalk(nil); mc != nil; mc = lispLMLwalk(mc) {
		if len(mc.rlocSet) == 0 && len(mc.rleSet) == 0 {
			out += fmt.Sprintf("  EID: %s, rloc-set: [], rle-set: []\n",
				mc.eidPrefix.lispPrintAddress(true))
			continue
		}
		if len(mc.rlocSet) != 0 {
			out += fmt.Sprintf("  EID: %s, rloc-set: ",
				mc.eidPrefix.lispPrintAddress(true))
			for i, rloc := range mc.rlocSet {
				keyID := ""
				if rloc.useKeyID != 0 {
					keyID = fmt.Sprintf(", key-id %d", rloc.useKeyID)
				}
				out += fmt.Sprintf("%s:%d%s",
					rloc.rloc.lispPrintAddress(false), rloc.encapPort,
					keyID)
				if i != len(mc.rlocSet)-1 {
					out += fmt.Sprintf(", ")
				}
			}
			out += fmt.Sprintf("\n")
		}
		if len(mc.rleSet) != 0 {
			out += fmt.Sprintf("  EID: %s, rle-set: ",
				mc.eidPrefix.lispPrintAddress(true))
			for i, rle := range mc.rleSet {
				out += fmt.Sprintf("%s:%d", rle.rloc.lispPrintAddress(false),
					rle.encapPort)
				if i != len(mc.rleSet)-1 {
					out += fmt.Sprintf(", ")
				}
			}
			out += fmt.Sprintf("\n")
		}
	}

	//
	// Display decap keys if any.
	//
	if len(lispDecapKeys) != 0 {
		out += fmt.Sprintf("\n%s\n", bold("LISP xTR Decap Keys"))
		for index, rloc := range lispDecapKeys {
			keyStr := "["
			for i := 0; i < len(rloc.keys); i++ {
				if rloc.keys[i] == nil {
					continue
				}
				if keyStr != "[" {
					keyStr += ", "
				}
				keyStr += fmt.Sprintf("%d", i)
			}
			keyStr += "]"
			out += fmt.Sprintf("  RLOC: %s, key-ids %s\n", index, keyStr)
		}
	}

	//
	// Final blank line.
	//
	out += fmt.Sprintf("\n")
	return (out)
}

//
// lispCreatePuntSocket
//
// Create named socket 'lispers.net-itr: is lispers.net directory.
//
func lispCreatePuntSocket() bool {
	var sa net.UnixAddr
	var found error

	sa.Name = lispersDir + "lispers.net-itr"
	sa.Net = "unixgram"

	for i := 0; i < 4; i++ {
		_, found = os.Stat(sa.Name)
		if found == nil {
			break
		}
		lprint("Punt socket %s does not exist, waiting ...", sa.Name)
		time.Sleep(time.Duration(i) * (time.Second * 2))
	}
	if found != nil {
		return (false)
	}
	lprint("Punt socket %s found", sa.Name)

	socket, err := net.DialUnix("unixgram", nil, &sa)
	if err != nil {
		lprint("net.DialUnix() failed: %s", err)
		return (false)
	}
	lispPuntSocket = socket

	//
	// Tell control-plane we have restarted.
	//
	lispSendRestart()
	return (true)
}

//
// lispPuntPacket
//
// Send IPC message to punt packet.
//
func lispPuntPacket(inputInterface string, seid lispAddress,
	deid lispAddress) {
	var ipc = map[string]string{"type": "discovery", "source-eid": "",
		"dest-eid": "", "interface": "", "instance-id": ""}

	//
	// Check rate-limiter before bothering the control-plane.
	//
	elapsed := time.Since(lispLastPunt).Nanoseconds()
	if elapsed <= lispRateLimiter {
		s := green(seid.lispPrintAddress(false))
		d := green(deid.lispPrintAddress(false))
		dprint("Rate-limit punt packet %s -> %s", s, d)
		return
	}

	if inputInterface == "?" {
		iid := fmt.Sprintf("%d", seid.instanceID)
		if seid.instanceID == 0xffffff {
			iid = "-1"
		}
		ipc["instance-id"] = iid
	} else {
		ipc["interface"] = inputInterface
		iid := lispNterfaces[inputInterface].instanceID
		ipc["instance-id"] = fmt.Sprintf("%d", iid)
	}
	ipc["source-eid"] = seid.lispPrintAddress(false)
	ipc["dest-eid"] = deid.lispPrintAddress(false)

	//
	// Encode in JSON and send on lispers.net-itr named socket.
	//
	jdata, err := json.Marshal(ipc)
	if err != nil {
		lprint("json.Marshal() failed: %s", err)
		return
	}

	lprint("Send %s: '%s'", bold("IPC"), jdata)
	lispPuntSocket.Write(jdata)
	lispLastPunt = time.Now()
}

//
// lispSendRestart
//
// Send IPC message to control-plane indicating that this data-plane has restarted.
//
func lispSendRestart() {
	var ipc = map[string]string{"type": "restart"}

	//
	// Encode in JSON and send on lispers.net-itr named socket.
	//
	jdata, err := json.Marshal(ipc)
	if err != nil {
		lprint("json.Marshal() failed: %s", err)
		return
	}

	lprint("Send %s: '%s'", bold("IPC"), jdata)
	lispPuntSocket.Write(jdata)
}

//
// lispStatsThread
//
// Peridoically send data-plane stats to the lispers.net control-plane.
//
func lispStatsThread() {
	pritIdle := false
	ipc := make(map[string]interface{}, 0)

	//
	// First IPC message is "type" : "statistics" which sends stats for map-
	// cache entry.
	//
	for {
		eids := make([]interface{}, 0)
		count := 0
		for mc := lispLMLwalk(nil); mc != nil; mc = lispLMLwalk(mc) {
			count++
			rlocs := make([]interface{}, 0)
			for j := range mc.rlocSet {
				rloc := &mc.rlocSet[j]
				if rloc.stats.packets == 0 {
					continue
				}

				ipcRloc := make(map[string]interface{}, 0)
				ipcRloc["rloc"] = rloc.rloc.lispPrintAddress(false)
				ipcRloc["port"] = fmt.Sprintf("%d", rloc.encapPort)
				ipcRloc["packet-count"] = rloc.stats.packets
				ipcRloc["byte-count"] = rloc.stats.bytes
				ipcRloc["seconds-last-packet"] =
					time.Since(rloc.stats.lastPacket).Seconds()
				rloc.stats.packets = 0
				rloc.stats.bytes = 0
				rlocs = append(rlocs, ipcRloc)
			}
			if len(rlocs) == 0 {
				continue
			}

			ipcEid := make(map[string]interface{}, 0)
			ipcEid["instance-id"] =
				fmt.Sprintf("%d", mc.eidPrefix.instanceID)
			ipcEid["eid-prefix"] = mc.eidPrefix.lispPrintAddress(false)
			ipcEid["rlocs"] = rlocs
			eids = append(eids, ipcEid)
		}

		if len(eids) != 0 {
			ipc["type"] = "statistics"
			ipc["entries"] = eids

			//
			// Encode in JSON and send on lispers.net-itr named socket.
			//
			jdata, err := json.Marshal(ipc)
			if err == nil {
				lprint("Send %s: '%s'", bold("IPC"), jdata)
				lispPuntSocket.Write(jdata)
			} else {
				lprint("json.Marshal() for stats messsage failed: %s", err)
			}
		} else if pritIdle {
			lprint("No change for %d map-cache entries, stats message "+
				"suppressed", count)
		}

		//
		// Second IPC message is "type" : "decap-stats" which sends global
		// stats for ETR and RTR decap processing.
		//
		dipc := make(map[string]interface{}, 0)
		changed := false
		for k, stats := range lispDecapStats {
			if stats.packets == 0 {
				continue
			}

			changed = true
			dipcStats := make(map[string]interface{}, 0)
			dipcStats["packet-count"] = stats.packets
			dipcStats["byte-count"] = stats.bytes
			dipcStats["seconds-last-packet"] =
				time.Since(stats.lastPacket).Seconds()
			dipc[k] = dipcStats
			stats.packets = 0
			stats.bytes = 0
		}

		//
		// Encode in JSON and send on lispers.net-itr named socket.
		//
		if changed {
			dipc["type"] = "decap-statistics"
			jdata, err := json.Marshal(dipc)
			if err == nil {
				lprint("Send %s: '%s'", bold("IPC"), jdata)
				lispPuntSocket.Write(jdata)
			} else {
				lprint("json.Marshal() for decap-stats messsage failed: %s",
					err)
			}
		} else if pritIdle {
			lprint("No change to decap-stats, message suppressed")
		}

		//
		// Send stats in 5 seconds if there was any change.
		//
		time.Sleep(5 * time.Second)
	}
}

/*
func lispIPCtyper(ipcMsg *[]byte) interface{} {

	type RawIPC struct {
		Type string
		Msg  interface{}
	}

	var rawLispIPCjson json.RawMessage

	rawIPC := UnTypedIPC{
		IPC: &ipc,
	}

	if err := json.Unmarshal(ipcMsg, &rawIPC); err != nil {
		lprint("error decoding IPC json message %s", err)
	}

	return rawIPC.Type

}
*/
