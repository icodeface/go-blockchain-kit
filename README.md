# Go Blockchain Kit


`go get github.com/icodeface/go-blockchain-kit`

`

## Example

```
package main

import (
	"fmt"
	"github.com/icodeface/go-blockchain-kit/keystore"
)


func main()  {
	mnomonic := "panel swim canvas organ claw luxury swarm quarter control december abandon able"
	k, _ := keystore.FromMnemonic(mnomonic, "")
	fmt.Println("master key is", k)

	child, err := k.DeriveChildKey("m/44'/0'/0'/0")
	if err != nil {
		fmt.Println(err)
	}

	child, err = child.DeriveChildKey("/1")
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(child, child.PublicKey())


	// Hash 160
	//hash160, _ := utils.Hash160(child.PublicKey().Key)
	//fmt.Println(hash160)
	//address, _ := utils.Hash160ToB58Address(hash160, 0)
	//fmt.Println(address)
	//fmt.Println(utils.B58AddressToHash160(address))


	// WIF
	//wif, _ := utils.WIFEncode(0x80, child.Key, true)
	//fmt.Println(wif)
	//fmt.Println(utils.WIFDecode(wif))

}

```