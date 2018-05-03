package keystore

import (
	"fmt"
	"github.com/icodeface/go-blockchain-kit/utils"
	"errors"
	"bytes"
	"strings"
)

const hash160Length = 20


func Hash160ToB58Address(hash160 []byte, addrType int) string {
	if len(hash160) != hash160Length {
		panic(errors.New(fmt.Sprintf("hash len is wrong: %d", len(hash160))))
	}

	buffer := new(bytes.Buffer)
	buffer.Write([]byte{byte(addrType)})
	buffer.Write(hash160)

	b, err := utils.AddChecksumToBytes(buffer.Bytes())
	if err != nil {
		panic(err)
	}

	nPad := 0
	for _, c := range b {
		if c == 0x00 {
			nPad += 1
		}else {
			break
		}
	}

	return fmt.Sprintf("%v%v", strings.Repeat("1", nPad), utils.Base58.EncodeToString(b))

}