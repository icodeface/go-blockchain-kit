package main

import (
	"fmt"
	"github.com/icodeface/go-blockchain-kit/keystore"
	"github.com/icodeface/go-blockchain-kit/utils"
)


func main()  {
	mnomonic := "panel swim canvas organ claw luxury swarm quarter control december abandon able"
	k, _ := keystore.FromMnemonic(mnomonic, "")
	fmt.Println("master is", k)

	child, err := k.DeriveChildKey("m/44'/0'/0'/0")
	if err != nil {
		fmt.Println(err)
	}

	child, err = child.DeriveChildKey("/1")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("child is ", child)
	hash160, _ := utils.Hash160(child.PublicKey().Key)
	fmt.Println(keystore.Hash160ToB58Address(hash160, 0))
}
