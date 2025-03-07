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
