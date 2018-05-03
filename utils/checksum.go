// copy from https://github.com/tyler-smith/go-bip32/blob/master/utils.go

package utils

import "errors"

var (
	// ErrInvalidChecksum is returned when deserializing a key with an incorrect
	// checksum
	ErrInvalidChecksum = errors.New("Checksum doesn't match")

)

func Checksum(data []byte) ([]byte, error) {
	hash, err := HashDoubleSha256(data)
	if err != nil {
		return nil, err
	}

	return hash[:4], nil
}

func AddChecksumToBytes(data []byte) ([]byte, error) {
	checksum, err := Checksum(data)
	if err != nil {
		return nil, err
	}
	return append(data, checksum...), nil
}