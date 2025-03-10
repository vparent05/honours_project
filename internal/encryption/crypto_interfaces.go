package encryption

import (
	"math/big"

	"github.com/jukuly/honours_project/internal/elliptic_curve"
)

type ECC_Params struct {
	G         *elliptic_curve.Point
	Order     *big.Int
	Threshold int
}

type TestCryptosystem interface {
	Setup()
	Encrypt(*big.Int) any
	Decrypt(any)
}
