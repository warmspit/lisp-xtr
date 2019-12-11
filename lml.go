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
// lml.go
//
// This file contains functions for the "Longest Match Lookup (LML)" support.
// It is used by xtr.go for doing map-cache lookups for forwarding. And is
// used by ipc.go to add and delete map-cache entries when the lispers.net
// control-plane tells it so.
//
// ---------------------------------------------------------------------------

package main

import "fmt"
import "net"

//
// If this is changed, change lmlClearHashTable() too.
//
var lispLMLcache [129]*lispHashTable

type lispHashTable struct {
	nextHt    int
	htCount   int
	hashTable [256]*lispMapCache // 8-bit hash
}

//
// lispLMLaddEntry
//
// Add an entry to the LML data structure.
//
func lispLMLaddEntry(mc *lispMapCache) {

	//
	// The EID-prefix slot in the array of hash-tables is based on its
	// prefix mask-length. Allocate memory for hash-table if this is the
	// first entry for the mask-length.
	//
	ht := lispLMLcache[mc.eidPrefix.maskLen]
	if ht == nil {
		ht = new(lispHashTable)
		lispLMLcache[mc.eidPrefix.maskLen] = ht
	}

	//
	// Hash the address to get a hash-table slot between the values of 0 and
	// 255. Insert at slot by "pushing down" all othe entries.
	//
	hash := lispLMLhash(mc.eidPrefix.address, mc.eidPrefix.maskLen)
	mc.nextMc = ht.hashTable[hash]
	ht.hashTable[hash] = mc
	ht.htCount++
}

//
// lispLMLdeleteEntry
//
// Remove entry from LML cache.
//
func lispLMLdeleteEntry(mc *lispMapCache) {

	//
	// The EID-prefix slot in the array of hash-tables is based on its
	// prefix mask-length. If the array slot has no hash-table allocated,
	// then the EID-prefix is not in the table.
	//
	ht := lispLMLcache[mc.eidPrefix.maskLen]
	if ht == nil {
		return
	}

	//
	// Hash the address to get a hash-table slot between the values of 0 and
	// 255. Search for map-cache entry pointer. Use pointer to pointer to
	// relink.
	//
	hash := lispLMLhash(mc.eidPrefix.address, mc.eidPrefix.maskLen)
	for mce := &ht.hashTable[hash]; *mce != nil; mce = &((*mce).nextMc) {
		if *mce == mc {
			*mce = mc.nextMc
			ht.htCount--
			return
		}
	}
}

//
// lispLMLlockup
//
// The longest match data structure is an array of hash tables. The first
// level array is indexed by mask-length. So lispLMLcache[129] is the first
// hash-table that is checked.
//
func lispLMLlockup(dest lispAddress) *lispMapCache {
	var start int

	if dest.lispIsIpv4() {
		start = 32
	} else if dest.lispIsIpv6() {
		start = 128
	} else {
		return (nil)
	}

	for i := start; i >= 0; i-- {
		ht := lispLMLcache[i]
		if ht == nil || ht.htCount == 0 {
			continue
		}

		hash := lispLMLhash(dest.address, i)
		for mce := ht.hashTable[hash]; mce != nil; mce = mce.nextMc {
			if mce.eidPrefix.lispMoreSpecific(dest) {
				return (mce)
			}
		}
	}
	return (nil)
}

//
// lispLMLexactLookup
//
// Call lispLMLlockup() and then compare the mask-lengths to determine if
// the match is an exact match.
//
func lispLMLexactLookup(address lispAddress) *lispMapCache {
	mc := lispLMLlockup(address)
	if mc == nil || mc.eidPrefix.maskLen != address.maskLen {
		return (nil)
	}
	return (mc)
}

//
// lispLMLhash
//
// Givene an address, return a hash value that is in range of 0 to 255. Make
// sure to zero out hosts bits so a prefix populated in a hash table can
// match the same hash table location with a destination used to be looked up.
//
func lispLMLhash(address net.IP, maskLen int) uint {
	hash := uint(0)
	mask := net.CIDRMask(maskLen, len(address)*8)

	for i := 0; i < len(address); i++ {
		if mask[i] == 0 {
			break
		}
		addrByte := uint(address[i]) & uint(mask[i])
		hash = hash ^ addrByte
	}
	return (hash)
}

//
// lispLMLshow
//
// Show internal representation of the LML data structure.
//
func lispLMLshow() {
	count := 0
	htCount := 0

	for i := 0; i < len(lispLMLcache); i++ {
		ht := lispLMLcache[i]
		if ht == nil || ht.htCount == 0 {
			continue
		}

		fmt.Printf("Hash table /%d, count %d\n", i, ht.htCount)
		slotCount := 0
		for hash, slot := range ht.hashTable {
			if slot == nil {
				continue
			}

			slotCount++
			fmt.Printf("  Hash 0x%x: ", hash)
			htCount = 0
			for mc := slot; mc != nil; mc = mc.nextMc {
				fmt.Printf("%s ", mc.eidPrefix.lispPrintAddress(true))
				count++
				htCount++
			}
			fmt.Printf("\n")
		}
		if slotCount != 0 {
			fmt.Printf("Average slot collision: %d\n", htCount/slotCount)
		}
	}

	fmt.Printf("Found %d entries\n", count)
}

//
// lispLMLwalk
//
// Walk each entry of the LML table and return a *lispMapCache. Passing
// in nil, gets you the first entry. Passing non-nil gets you the entry
// after the pointer passed in. Return nil when end of table.
//
func lispLMLwalk(mc *lispMapCache) *lispMapCache {
	found := (mc == nil)

	for i := 0; i < len(lispLMLcache); i++ {
		ht := lispLMLcache[i]
		if ht == nil || ht.htCount == 0 {
			continue
		}

		for _, slot := range ht.hashTable {
			for mce := slot; mce != nil; mce = mce.nextMc {
				if found {
					return (mce)
				}
				if mce == mc {
					found = true
				}
			}
		}
	}
	return (nil)
}

//
// lmlClearHashTable
//
// Remove all entries from LML hash-table.
//
func lmlClearHashTable() {
	var newCache [129]*lispHashTable

	lispLMLcache = newCache
}
