package main

import (
	"encoding/hex"
	"fmt"
)

func bToHex(b []byte) string {
	resp := ""
	for i, bt := range b {
		btAsString := hex.EncodeToString([]byte{bt})
		if i > 0 {
			resp += " "
		}
		resp += btAsString
	}
	return resp
}

func bToUUID(b []byte, bIsInReverse bool) string {
	if len(b) != 16 {
		fatal("a uuid should have a length of 16 bytes")
	}

	if bIsInReverse {
		b = reverse(b)
	}

	encoded := hex.EncodeToString(b)
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:])
}
