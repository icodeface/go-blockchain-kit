package utils

import (
	"fmt"
	"errors"
	"bytes"
	"strings"
)

const hash160Length = 20
const b58addressLength = 34


func Hash160ToB58Address(hash160 []byte, addrType int) (string, error) {
	if len(hash160) != hash160Length {
		panic(errors.New(fmt.Sprintf("hash len is wrong: %d", len(hash160))))
	}

	buffer := new(bytes.Buffer)
	buffer.Write([]byte{byte(addrType)})
	buffer.Write(hash160)

	return encodeBase58Check(buffer.Bytes())
}

func B58AddressToHash160(address string) (hash160 []byte, addrType int, err error) {
	if len(address) != b58addressLength {
		panic(errors.New(fmt.Sprintf("address len is wrong: %d", len(hash160))))
	}

	data, err := decodeBase58Check(address)
	if err != nil {
		return nil, 0, err
	}
	return data[len(data)-hash160Length:], int(data[0]), nil
}

func IsB58Address(address string) (bool) {

	hash160, addrType, err := B58AddressToHash160(address)
	if err != nil {
		return false
	}

	// todo should check addrType

	addr2, err := Hash160ToB58Address(hash160, addrType)
	if err != nil {
		return false
	}

	return strings.Compare(address, addr2) == 0
}