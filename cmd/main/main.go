package main

import (
	"fmt"
	"math/big"
	"time"

	"github.com/jukuly/honours_project/internal/bc_ectss"
	"github.com/jukuly/honours_project/internal/elliptic_curve"
	"github.com/jukuly/honours_project/internal/encryption"
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
	params := &encryption.ECC_Params{
		G:         G,
		Order:     q,
		Threshold: 3,
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

	msg := big.NewInt(5234583490578210874)
	tag, _ := utils.StringToInt("124353464568757742342366456234")

	bcectssSys := bc_ectss.TestBCECTSSEncryption{
		Params: params,
		Ids:    ids,
		Tag:    tag,
		DecrypterIds: []*big.Int{
			big.NewInt(1),
			big.NewInt(2),
			big.NewInt(3),
			big.NewInt(4)},
	}

	elgamalSys := threshold_elgamal.TestElgamalEncryption{
		Params: params,
		Ids:    ids,
		DecrypterIds: []*big.Int{
			big.NewInt(1),
			big.NewInt(2),
			big.NewInt(3),
			big.NewInt(4)},
	}

	benchmark(&bcectssSys, "BCECTSS", 10, msg)
	benchmark(&elgamalSys, "Elgamal", 10, msg)
}

func benchmark(sys encryption.TestCryptosystem, name string, n int, plain *big.Int) {
	var totalS time.Duration = 0
	var totalE time.Duration = 0
	var totalD time.Duration = 0

	for range n {
		start := time.Now()
		sys.Setup()
		totalS += time.Since(start)

		start = time.Now()
		cipher := sys.Encrypt(plain)
		totalE += time.Since(start)

		start = time.Now()
		sys.Decrypt(cipher)
		totalD += time.Since(start)
	}
	fmt.Printf("%s Setup Took: %vms\n", name, float32(totalS.Milliseconds())/float32(n))
	fmt.Printf("%s Encryption Took: %vms\n", name, float32(totalE.Milliseconds())/float32(n))
	fmt.Printf("%s Decryption Took: %vms\n", name, float32(totalD.Milliseconds())/float32(n))
}
