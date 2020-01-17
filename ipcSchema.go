package main

type databaseMappings struct {
	DatabaseMappings []struct {
		EidPrefix  string `json:"eid-prefix"`
		InstanceID string `json:"instance-id"`
	} `json:"database-mappings"`
	Type string `json:"type"`
}

type decapKeys struct {
	Keys []struct {
		Decrypt_key string `json:"decrypt-key"`
		Icv_key     string `json:"icv-key"`
		Key_id      string `json:"key-id"`
	} `json:"keys"`
	Port string `json:"port"`
	Rloc string `json:"rloc"`
	Type string `json:"type"`
}

type decapStatistics struct {
	ICV_error struct {
		Byte_count          string `json:"byte-count"`
		Packet_count        string `json:"packet-count"`
		Seconds_last_packet string `json:"seconds-last-packet"`
	} `json:"ICV-error"`
	Bad_inner_version struct {
		Byte_count          string `json:"byte-count"`
		Packet_count        string `json:"packet-count"`
		Seconds_last_packet string `json:"seconds-last-packet"`
	} `json:"bad-inner-version"`
	Checksum_error struct {
		Byte_count          string `json:"byte-count"`
		Packet_count        string `json:"packet-count"`
		Seconds_last_packet string `json:"seconds-last-packet"`
	} `json:"checksum-error"`
	Good_packets struct {
		Byte_count          string `json:"byte-count"`
		Packet_count        string `json:"packet-count"`
		Seconds_last_packet string `json:"seconds-last-packet"`
	} `json:"good-packets"`
	No_decrypt_key struct {
		Byte_count          string `json:"byte-count"`
		Packet_count        string `json:"packet-count"`
		Seconds_last_packet string `json:"seconds-last-packet"`
	} `json:"no-decrypt-key"`
	Outer_header_error struct {
		Byte_count          string `json:"byte-count"`
		Packet_count        string `json:"packet-count"`
		Seconds_last_packet string `json:"seconds-last-packet"`
	} `json:"outer-header-error"`
	Type string `json:"type"`
}

type discovery struct {
	Dest_eid    string `json:"dest-eid"`
	Instance_id string `json:"instance-id"`
	Interface   string `json:"interface"`
	Source_eid  string `json:"source-eid"`
	Type        string `json:"type"`
}

type etrNatPort struct {
	Port string `json:"port"`
	Type string `json:"type"`
}

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
type interfaces struct {
	Interfaces []struct {
		Instance_id string `json:"instance-id"`
		Interface   string `json:"interface"`
	} `json:"interfaces"`
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

type itrCryptoPort struct {
	Port string `json:"port"`
	Type string `json:"type"`
}

type restart struct {
	Type string `json:"type"`
}

type rlocs struct{}

type statistics struct {
	Entries []struct {
		Eid_prefix  string `json:"eid-prefix"`
		Instance_id string `json:"instance-id"`
		Rlocs       []struct {
			Byte_count          string `json:"byte-count"`
			Packet_count        string `json:"packet-count"`
			Rloc                string `json:"rloc"`
			Seconds_last_packet string `json:"seconds-last-packet"`
		} `json:"rlocs"`
	} `json:"entries"`
	Type string `json:"type"`
}
