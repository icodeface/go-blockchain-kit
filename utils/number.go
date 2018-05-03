// copy from https://github.com/tyler-smith/go-bip32/blob/master/utils.go

package utils

import "encoding/binary"

func Uint32Bytes(i uint32) []byte {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, i)
	return bytes
}