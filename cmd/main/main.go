package main

import (
	"fmt"
	"math/big"
	"time"

	"github.com/jukuly/honours_project/internal/bc_ectss"
	"github.com/jukuly/honours_project/internal/elliptic_curve"
	"github.com/jukuly/honours_project/internal/threshold_elgamal"
	"github.com/jukuly/honours_project/internal/utils"
)

func main() {
	p, _ := utils.StringToInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
	q, _ := utils.StringToInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	curve := &elliptic_curve.EllipticCurve{A: big.NewInt(0), B: big.NewInt(7), P: p}
	g_x, _ := utils.StringToInt("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	g_y, _ := utils.StringToInt("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
	G, _ := curve.Point(g_x, g_y)
	params_elgamal := &threshold_elgamal.Elgamal_Params{
		G:         G,
		Order:     q,
		Threshold: 3,
	}
	params_bcectss := &bc_ectss.BCECTSS_Params{
		G:         params_elgamal.G,
		Order:     params_elgamal.Order,
		Threshold: params_elgamal.Threshold,
	}
	ids := []*big.Int{
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
		big.NewInt(4),
		big.NewInt(5),
		big.NewInt(6),
		big.NewInt(7),
	}

	msg_elgamal := params_elgamal.G.Multiply(big.NewInt(5234583490578210874))
	msg_bcectss := params_elgamal.G.Multiply(big.NewInt(5234583490578210874))
	tag, _ := utils.StringToInt("124353464568757742342366456234")

	benchmark(
		func() []any {
			return setupElgamal(params_elgamal, ids)
		},
		func(in []any) []any {
			private := in[0]
			global := in[1].(*elliptic_curve.Point)

			cipher, _ := params_elgamal.Encrypt(msg_elgamal, global)
			return []any{cipher, private}
		},
		func(in []any) {
			cipher := in[0].(*threshold_elgamal.Ciphertext)
			private := in[1].([]*big.Int)

			decryptElgamal(params_elgamal, cipher, private)
		},
		"Elgamal",
		10,
	)

	benchmark(
		func() []any {
			return setupBCECTSS(params_bcectss, ids)
		},
		func(in []any) []any {
			parties := in[0]
			Q := in[1].(*elliptic_curve.Point)

			cipher, _ := params_bcectss.Encrypt(msg_bcectss, tag, Q)
			return []any{cipher, parties}
		},
		func(in []any) {
			cipher := in[0].(*bc_ectss.Ciphertext)
			parties := in[1].([]*bc_ectss.BCECTSS)

			decryptBCECTSS(cipher, tag, parties)
		},
		"BCECTSS",
		10,
	)
}

func benchmark(setup func() []any, encrypt func([]any) []any, decrypt func([]any), name string, n int) {
	var totalS time.Duration = 0
	var totalE time.Duration = 0
	var totalD time.Duration = 0

	for range n {
		start := time.Now()
		s := setup()
		totalS += time.Since(start)

		start = time.Now()
		e := encrypt(s)
		totalE += time.Since(start)

		start = time.Now()
		decrypt(e)
		totalD += time.Since(start)
	}
	fmt.Printf("%s Setup Took: %vms\n", name, float32(totalS.Milliseconds())/float32(n))
	fmt.Printf("%s Encryption Took: %vms\n", name, float32(totalE.Milliseconds())/float32(n))
	fmt.Printf("%s Decryption Took: %vms\n", name, float32(totalD.Milliseconds())/float32(n))
}

func setupBCECTSS(params *bc_ectss.BCECTSS_Params, ids []*big.Int) []any {
	parties := make([]*bc_ectss.BCECTSS, len(ids))
	for i := range parties {
		parties[i] = bc_ectss.New(params, ids[i])
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

	return []any{parties, parties[0].Q}
}

func decryptBCECTSS(cipher *bc_ectss.Ciphertext, tag *big.Int, parties []*bc_ectss.BCECTSS) {
	partialSignatures := make([]*bc_ectss.Signature, 4)
	for i := range 4 {
		partialSignatures[i] = parties[i].PartialSignature(tag, []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)})
	}

	finalSignature, _ := parties[0].CombineSignature(partialSignatures)

	bc_ectss.Decrypt(cipher, finalSignature)
}

func setupElgamal(params *threshold_elgamal.Elgamal_Params, ids []*big.Int) []any {
	_, private, global := params.GenerateKeys(ids)

	return []any{private, global}
}

func decryptElgamal(params *threshold_elgamal.Elgamal_Params, cipher *threshold_elgamal.Ciphertext, private []*big.Int) {
	shares := make([]*elliptic_curve.Point, 4)
	for i := range shares {
		shares[i] = threshold_elgamal.PartialDecrypt(cipher, private[i])
	}

	params.Decrypt(shares, cipher, []*big.Int{
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
		big.NewInt(4),
	})
}
