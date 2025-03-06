package bc_ectss

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/jukuly/honours_project/internal/elliptic_curve"
)

type node struct {
	id  *big.Int
	a   []*big.Int
	eta []*elliptic_curve.Point
	sk  *big.Int
	pk  *elliptic_curve.Point
}

type Signature struct {
	Point *elliptic_curve.Point
	L     *big.Int
	Beta  *big.Int
}

func NewNode(id int) *node {
	node := node{}
	node.id = big.NewInt(int64(id))
	node.a = make([]*big.Int, GetSystem().Threshold)

	for i := 0; i < GetSystem().Threshold; i++ {
		node.a[i], _ = rand.Int(rand.Reader, GetSystem().Order.Sub(GetSystem().Order, big.NewInt(1)))
		node.a[i].Add(node.a[i], big.NewInt(1))
	}

	node.eta = make([]*elliptic_curve.Point, GetSystem().Threshold)
	for i := 0; i < GetSystem().Threshold; i++ {
		node.eta[i] = GetSystem().G.Multiply(node.a[i])
	}

	return &node
}

func (n *node) f(x *big.Int) *big.Int {
	res := big.NewInt(0)
	var temp *big.Int
	for i := 0; i < len(n.a); i++ {
		res.Add(res, temp.Mul(n.a[i], temp.Exp(x, big.NewInt(int64(i)), GetSystem().Order)))
	}
	return res.Mod(res, GetSystem().Order)
}

func (n *node) Chi() *big.Int {
	chi := big.NewInt(1)
	var temp *big.Int
	for i := 0; i < GetSystem().Threshold; i++ {
		id_j := GetSystem().Users[i].id
		if id_j == n.id {
			continue
		}
		chi.Mul(chi, temp.Neg(id_j))
		chi.Mul(chi, temp.ModInverse(temp.Sub(n.id, id_j), GetSystem().Order))
	}
	return chi.Mod(chi, GetSystem().Order)
}

func (n *node) SetKeys() error {
	for _, n_i := range GetSystem().Users {
		if n_i.id == n.id {
			continue
		}
		if !n.verifySecretShare(n_i) {
			return fmt.Errorf("secret share verification failed")
		}
	}

	n.sk = big.NewInt(0)
	for _, n_i := range GetSystem().Users {
		n.sk.Add(n.sk, n_i.f(n.id))
	}

	n.pk = GetSystem().G.Multiply(n.sk)
	return nil
}

// verify the secret share from node n_j to node n_i
func (n_i *node) verifySecretShare(n_j *node) bool {
	rhs := make([]*elliptic_curve.Point, GetSystem().Threshold)
	var temp *big.Int
	for i := 0; i < GetSystem().Threshold; i++ {
		n_j.eta[i].Multiply(temp.Exp(n_i.id, big.NewInt(int64(i)), GetSystem().Order))
	}
	rhsSum, _ := elliptic_curve.PointSum(rhs)

	return GetSystem().G.Multiply(n_j.f(n_i.id)).Equals(rhsSum)
}

func (n *node) GetPartialSignature(message *big.Int) *Signature {
	k, _ := rand.Int(rand.Reader, GetSystem().Order.Sub(GetSystem().Order, big.NewInt(1)))
	k.Add(k, big.NewInt(1))

	e := Hash(message)

	point := GetSystem().G.Multiply(k)

	r := point.X.Mod(point.X, GetSystem().Order)
	if r.Cmp(big.NewInt(0)) == 0 {
		r = big.NewInt(1)
	}

	beta, _ := rand.Int(rand.Reader, GetSystem().Order.Sub(GetSystem().Order, big.NewInt(1)))
	beta.Add(beta, big.NewInt(1))

	var temp *big.Int
	alpha := temp.Mul(temp.Sub(k, temp.Mul(beta, message)), temp.ModInverse(r, GetSystem().Order))
	alpha.Mod(alpha, GetSystem().Order)

	chi := n.Chi()
	l := temp.Mod(temp.Add(temp.Mul(alpha, r), temp.Mul(temp.Mul(e, chi), n.sk)), GetSystem().Order)

	return &Signature{point, l, beta}
}

func (n *node) VerifyPartialSignature(message *big.Int, sig *Signature) bool {

	var temp *big.Int
	gamma := temp.Mod(temp.Add(sig.L, temp.Mul(sig.Beta, message)), GetSystem().Order)

	e := Hash(message)

	chi := n.Chi()
	point, _ := GetSystem().G.Multiply(gamma).Add(n.pk.Multiply(e.Mul(e, chi)).Negate())

	return point.Equals(sig.Point)
}

func GetSignature(partialSignatures []*Signature) *Signature {
	l := big.NewInt(0)
	beta := big.NewInt(0)
	var point *elliptic_curve.Point
	for _, sig := range partialSignatures {
		l.Mod(l.Add(l, sig.L), GetSystem().Order)
		beta.Mod(beta.Add(beta, sig.Beta), GetSystem().Order)
		point.Add(sig.Point)
	}
	return &Signature{point, l, beta}
}

func VerifySignature(message *big.Int, sig *Signature) bool {
	var temp *big.Int
	gamma := temp.Mod(temp.Add(sig.L, temp.Mul(sig.Beta, message)), GetSystem().Order)

	e := Hash(message)
	point, _ := GetSystem().G.Multiply(gamma).Add(GetSystem().PublicKey.Multiply(e).Negate())

	return point.Equals(sig.Point)
}
