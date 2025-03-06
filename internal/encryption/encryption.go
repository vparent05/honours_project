package encryption

import (
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/jukuly/honours_project/internal/bc_ectss"
	"github.com/jukuly/honours_project/internal/elliptic_curve"
)

type Ciphertext struct {
	c1 *elliptic_curve.Point
	c2 *big.Int
	c3 *elliptic_curve.Point
	c4 *elliptic_curve.Point
}

func Encrypt(plaintext *elliptic_curve.Point, tag *big.Int) (*Ciphertext, error) {
	var temp *big.Int
	alpha, _ := rand.Int(rand.Reader, bc_ectss.GetSystem().Order)

	c1, err := bc_ectss.GetSystem().PublicKey.Multiply(temp.Mul(alpha, bc_ectss.Hash(tag))).Add(plaintext)
	if err != nil {
		return nil, errors.New("plaintext is not on the system curve")
	}

	c2 := temp.Neg(alpha)
	c3 := bc_ectss.GetSystem().G.Multiply(alpha)
	c4 := bc_ectss.GetSystem().G.Multiply(temp.Mul(alpha, bc_ectss.Hash(tag)))

	return &Ciphertext{c1, c2, c3, c4}, nil
}

func Decrypt(ciphertext *Ciphertext, signature *bc_ectss.Signature) (*elliptic_curve.Point, error) {
	dotProduct, err := elliptic_curve.PointSum([]*elliptic_curve.Point{
		signature.Point.Multiply(ciphertext.c2),
		ciphertext.c3.Multiply(signature.L),
		ciphertext.c4.Multiply(signature.Beta),
	})
	if err != nil {
		return nil, errors.New("invalid ciphertext")
	}

	decrypted, err := ciphertext.c1.Add(dotProduct.Negate())
	if err != nil {
		return nil, errors.New("invalid ciphertext")
	}

	return decrypted, nil
}
