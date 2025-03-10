package utils

import (
	"errors"
	"math/big"
)

func StringToInt(str string) (*big.Int, error) {
	res := big.NewInt(0)
	res, success := res.SetString(str, 0)

	if !success {
		return nil, errors.New("invalid string")
	}

	return res, nil
}

// returns the lagrange coefficient modulo m of id_i
func Chi(id_i *big.Int, ids []*big.Int, m *big.Int) *big.Int {
	chi := big.NewInt(1)
	for _, id := range ids {
		if id.Cmp(id_i) == 0 {
			continue
		}
		chi.Mul(chi, PureNeg(id))
		chi.Mul(chi, PureModInverse(PureSub(id_i, id), m))
	}
	return chi.Mod(chi, m)
}

func PureAdd(x, y *big.Int) *big.Int {
	return new(big.Int).Add(x, y)
}

func PureMul(x, y *big.Int) *big.Int {
	return new(big.Int).Mul(x, y)
}

func PureSub(x, y *big.Int) *big.Int {
	return new(big.Int).Sub(x, y)
}

func PureExp(x, y, m *big.Int) *big.Int {
	return new(big.Int).Exp(x, y, m)
}

func PureNeg(x *big.Int) *big.Int {
	return new(big.Int).Neg(x)
}

func PureModInverse(g, n *big.Int) *big.Int {
	return new(big.Int).ModInverse(g, n)
}

func PureMod(x, y *big.Int) *big.Int {
	return new(big.Int).Mod(x, y)
}
