package main

import (
	"fmt"
	"github.com/icodeface/go-blockchain-kit/keystore"
	"github.com/icodeface/go-blockchain-kit/utils"
	"encoding/hex"
)


func main()  {
	mnomonic := "panel swim canvas organ claw luxury swarm quarter control december abandon able"
	k, _ := keystore.FromMnemonic(mnomonic, "")
	fmt.Println("k is", k)
	child, err := k.DeriveChildKey("m/44'/0'/0'/0")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("child is ", child)

	child, err = child.DeriveChildKey("/0")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("child is ", child)
	hash160, _ := utils.Hash160(child.PublicKey().Key)
	hash160_str := hex.EncodeToString(hash160)
	fmt.Println(hash160_str)
}
