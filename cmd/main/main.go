package main

import (
	"fmt"
	"math/big"

	"github.com/jukuly/honours_project/internal/bc_ectss"
	"github.com/jukuly/honours_project/internal/elliptic_curve"
	"github.com/jukuly/honours_project/internal/utils"
)

func main() {
	fmt.Printf("Initializing with curve secp256k1\n")

	p, _ := utils.StringToInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
	q, _ := utils.StringToInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")

	curve := &elliptic_curve.EllipticCurve{A: big.NewInt(0), B: big.NewInt(7), P: p}

	g_x, _ := utils.StringToInt("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	g_y, _ := utils.StringToInt("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
	G, _ := curve.Point(g_x, g_y)

	params := &bc_ectss.BCECTSS_Params{
		G:         G,
		Order:     q,
		Threshold: 3,
	}

	parties := []*bc_ectss.BCECTSS{
		bc_ectss.New(params, big.NewInt(1)),
		bc_ectss.New(params, big.NewInt(2)),
		bc_ectss.New(params, big.NewInt(3)),
		bc_ectss.New(params, big.NewInt(4)),
		bc_ectss.New(params, big.NewInt(5)),
		bc_ectss.New(params, big.NewInt(6)),
		bc_ectss.New(params, big.NewInt(7)),
	}

	// secret share from j to i
	secretShares := make([][]*big.Int, 7)
	eta0 := make([]*elliptic_curve.Point, 7)

	for i, p_i := range parties {
		eta0[i] = p_i.Eta[0]
		secretShares[i] = make([]*big.Int, 7)
		for j, p_j := range parties {
			secretShares[i][j] = p_j.SecretShare(p_i.Id)
		}
	}

	for i, p := range parties {
		p.SetPersonalKeys(secretShares[i])
		p.SetSystemKey(eta0)
	}

	msg, _ := utils.StringToInt("0x1234567890")

	partialSignatures := make([]*bc_ectss.Signature, 4)
	for i := range 4 {
		partialSignatures[i] = parties[i].PartialSignature(msg, []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)})
	}

	finalSignature, _ := parties[0].CombineSignature(partialSignatures)

	valid := parties[0].VerifySignature(msg, finalSignature)

	fmt.Printf("%t\n", valid)
}
