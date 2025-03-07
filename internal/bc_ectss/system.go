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

type Ciphertext struct {
	c1 *elliptic_curve.Point
	c2 *big.Int
	c3 *elliptic_curve.Point
	c4 *elliptic_curve.Point
}

func (sys *System) hash(plain *big.Int) *big.Int {
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

func (sys *System) NewNode(id int) *node {
	node := node{}
	node.id = big.NewInt(int64(id))
	node.a = make([]*big.Int, sys.Threshold)

	for i := 0; i < sys.Threshold; i++ {
		node.a[i], _ = rand.Int(rand.Reader, sys.Order.Sub(sys.Order, big.NewInt(1)))
		node.a[i].Add(node.a[i], big.NewInt(1))
	}

	node.eta = make([]*elliptic_curve.Point, sys.Threshold)
	for i := 0; i < sys.Threshold; i++ {
		node.eta[i] = sys.G.Multiply(node.a[i])
	}

	node.system = sys

	return &node
}

func (sys *System) GetSignature(partialSignatures []*Signature) *Signature {
	l := big.NewInt(0)
	beta := big.NewInt(0)
	var point *elliptic_curve.Point
	for _, sig := range partialSignatures {
		l.Mod(l.Add(l, sig.L), sys.Order)
		beta.Mod(beta.Add(beta, sig.Beta), sys.Order)
		point.Add(sig.Point)
	}
	return &Signature{point, l, beta}
}

func (sys *System) VerifySignature(message *big.Int, sig *Signature) bool {
	var temp *big.Int
	gamma := temp.Mod(temp.Add(sig.L, temp.Mul(sig.Beta, message)), sys.Order)

	e := sys.hash(message)
	point, _ := sys.G.Multiply(gamma).Add(sys.PublicKey.Multiply(e).Negate())

	return point.Equals(sig.Point)
}

func (sys *System) Encrypt(plaintext *elliptic_curve.Point, tag *big.Int) (*Ciphertext, error) {
	var temp *big.Int
	alpha, _ := rand.Int(rand.Reader, sys.Order)

	c1, err := sys.PublicKey.Multiply(temp.Mul(alpha, sys.hash(tag))).Add(plaintext)
	if err != nil {
		return nil, errors.New("plaintext is not on the system curve")
	}

	c2 := temp.Neg(alpha)
	c3 := sys.G.Multiply(alpha)
	c4 := sys.G.Multiply(temp.Mul(alpha, sys.hash(tag)))

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
