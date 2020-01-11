package main

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
