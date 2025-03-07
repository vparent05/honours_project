package bc_ectss

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/jukuly/honours_project/internal/elliptic_curve"
)

type node struct {
	id     *big.Int
	a      []*big.Int
	eta    []*elliptic_curve.Point
	sk     *big.Int
	pk     *elliptic_curve.Point
	system *System
}

type Signature struct {
	Point *elliptic_curve.Point
	L     *big.Int
	Beta  *big.Int
}

func (n *node) f(x *big.Int) *big.Int {
	res := big.NewInt(0)
	var temp *big.Int
	for i := 0; i < len(n.a); i++ {
		res.Add(res, temp.Mul(n.a[i], temp.Exp(x, big.NewInt(int64(i)), n.system.Order)))
	}
	return res.Mod(res, n.system.Order)
}

func (n *node) Chi() *big.Int {
	chi := big.NewInt(1)
	var temp *big.Int
	for i := 0; i < n.system.Threshold; i++ {
		id_j := n.system.Users[i].id
		if id_j == n.id {
			continue
		}
		chi.Mul(chi, temp.Neg(id_j))
		chi.Mul(chi, temp.ModInverse(temp.Sub(n.id, id_j), n.system.Order))
	}
	return chi.Mod(chi, n.system.Order)
}

func (n *node) SetKeys() error {
	for _, n_i := range n.system.Users {
		if n_i.id == n.id {
			continue
		}
		if !n.verifySecretShare(n_i) {
			return fmt.Errorf("secret share verification failed")
		}
	}

	n.sk = big.NewInt(0)
	for _, n_i := range n.system.Users {
		n.sk.Add(n.sk, n_i.f(n.id))
	}

	n.pk = n.system.G.Multiply(n.sk)
	return nil
}

// verify the secret share from node n_j to node n_i
func (n_i *node) verifySecretShare(n_j *node) bool {
	if n_i.system != n_j.system {
		return false
	}

	rhs := make([]*elliptic_curve.Point, n_i.system.Threshold)
	var temp *big.Int
	for i := 0; i < n_i.system.Threshold; i++ {
		n_j.eta[i].Multiply(temp.Exp(n_i.id, big.NewInt(int64(i)), n_i.system.Order))
	}
	rhsSum, _ := elliptic_curve.PointSum(rhs)

	return n_i.system.G.Multiply(n_j.f(n_i.id)).Equals(rhsSum)
}

func (n *node) GetPartialSignature(message *big.Int) *Signature {
	k, _ := rand.Int(rand.Reader, n.system.Order.Sub(n.system.Order, big.NewInt(1)))
	k.Add(k, big.NewInt(1))

	e := n.system.hash(message)

	point := n.system.G.Multiply(k)

	r := point.X.Mod(point.X, n.system.Order)
	if r.Cmp(big.NewInt(0)) == 0 {
		r = big.NewInt(1)
	}

	beta, _ := rand.Int(rand.Reader, n.system.Order.Sub(n.system.Order, big.NewInt(1)))
	beta.Add(beta, big.NewInt(1))

	var temp *big.Int
	alpha := temp.Mul(temp.Sub(k, temp.Mul(beta, message)), temp.ModInverse(r, n.system.Order))
	alpha.Mod(alpha, n.system.Order)

	chi := n.Chi()
	l := temp.Mod(temp.Add(temp.Mul(alpha, r), temp.Mul(temp.Mul(e, chi), n.sk)), n.system.Order)

	return &Signature{point, l, beta}
}

func (n *node) VerifyPartialSignature(message *big.Int, sig *Signature) bool {

	var temp *big.Int
	gamma := temp.Mod(temp.Add(sig.L, temp.Mul(sig.Beta, message)), n.system.Order)

	e := n.system.hash(message)

	chi := n.Chi()
	point, _ := n.system.G.Multiply(gamma).Add(n.pk.Multiply(e.Mul(e, chi)).Negate())

	return point.Equals(sig.Point)
}
