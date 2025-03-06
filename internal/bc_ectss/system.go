package bc_ectss

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/jukuly/honours_project/internal/elliptic_curve"
)

type System struct {
	G         *elliptic_curve.Point
	Order     *big.Int
	Users     []*node
	Threshold int
	PublicKey *elliptic_curve.Point
}

func (sys *System) Hash(plain *big.Int) *big.Int {
	hash := sha256.New()
	hash.Write(plain.Bytes())

	var digest *big.Int
	digest.SetBytes(hash.Sum(nil))
	return digest.Mod(digest, sys.Order)
}

func (s *System) SetPublicKey() *elliptic_curve.Point {
	s.PublicKey = nil

	for _, user := range s.Users {
		s.PublicKey, _ = s.PublicKey.Add(user.eta[0])
	}

	return s.PublicKey
}

type Ciphertext struct {
	c1 *elliptic_curve.Point
	c2 *big.Int
	c3 *elliptic_curve.Point
	c4 *elliptic_curve.Point
}

func (sys *System) Encrypt(plaintext *elliptic_curve.Point, tag *big.Int) (*Ciphertext, error) {
	var temp *big.Int
	alpha, _ := rand.Int(rand.Reader, sys.Order)

	c1, err := sys.PublicKey.Multiply(temp.Mul(alpha, sys.Hash(tag))).Add(plaintext)
	if err != nil {
		return nil, errors.New("plaintext is not on the system curve")
	}

	c2 := temp.Neg(alpha)
	c3 := sys.G.Multiply(alpha)
	c4 := sys.G.Multiply(temp.Mul(alpha, sys.Hash(tag)))

	return &Ciphertext{c1, c2, c3, c4}, nil
}

func Decrypt(ciphertext *Ciphertext, signature *Signature) (*elliptic_curve.Point, error) {
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
