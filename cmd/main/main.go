package main

import (
	"fmt"
)

func main() {
	fmt.Printf("Initializing with curve secp256k1")

	/*p := big.NewInt(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
	q := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

	curve := elliptic_curve.EllipticCurve(big.NewInt(0), big.NewInt(7), p)
	G, err := curve.Point(
		big.NewInt(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798),
		big.NewInt(0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8),
	)

	bc_ectss.SetSystem(&bc_ectss.System{
		G:         G,
		Order:     q,
		Threshold: 10,
	})

	identities := []int{}
	bc_ectss.GetSystem().AddUsers(identities)*/
}
