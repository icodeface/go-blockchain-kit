package keystore

import (
	"fmt"
	"github.com/icodeface/go-blockchain-kit/utils"
	"errors"
	"bytes"
	"strings"
)

const hash160Length = 20
const b58addressLength = 34

func baseDecode(s string) ([]byte, error) {
	nPad := 0
	for _, c := range s {
		if c == '1' {
			nPad += 1
		}else {
			break
		}
	}
	ss := string(s[nPad:])
	b, err := utils.Base58.DecodeString(ss)
	if err != nil {
		return nil, err
	}
	buffer := new(bytes.Buffer)
	buffer.Write(make([]byte, nPad))
	buffer.Write(b)
	return buffer.Bytes(), nil
}

func baseEncode(b []byte) (string, error) {
	nPad := 0
	for _, c := range b {
		if c == 0x00 {
			nPad += 1
		}else {
			break
		}
	}
	return fmt.Sprintf("%v%v", strings.Repeat("1", nPad), utils.Base58.EncodeToString(b)), nil
}


func Hash160ToB58Address(hash160 []byte, addrType int) (string, error) {
	if len(hash160) != hash160Length {
		panic(errors.New(fmt.Sprintf("hash len is wrong: %d", len(hash160))))
	}

	buffer := new(bytes.Buffer)
	buffer.Write([]byte{byte(addrType)})
	buffer.Write(hash160)

	b, err := utils.AddChecksumToBytes(buffer.Bytes())
	if err != nil {
		return "", nil
	}
	return baseEncode(b)
}

func B58AddressToHash160(address string) (hash160 []byte, addrType int, err error) {
	if len(address) != b58addressLength {
		panic(errors.New(fmt.Sprintf("address len is wrong: %d", len(hash160))))
	}

	b, err := baseDecode(address)
	if err != nil {
		return nil, 0, err
	}

	data, err := utils.ValidateChecksum(b)
	if err != nil {
		return nil, 0, err
	}
	return data[len(data)-hash160Length:], int(data[0]), nil
}