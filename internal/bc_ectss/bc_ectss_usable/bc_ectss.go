package bc_ectss_usable

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	"github.com/jukuly/honours_project/internal/elliptic_curve"
)

type BCECTSS_Params struct {
	G         *elliptic_curve.Point
	Order     *big.Int
	Threshold int
}

type _BCECTSS struct {
	id     *big.Int
	a      []*big.Int
	eta    []*elliptic_curve.Point
	sk     *big.Int
	pk     *elliptic_curve.Point
	Q      *elliptic_curve.Point
	Params *BCECTSS_Params
}

type Signature struct {
	Point *elliptic_curve.Point
	L     *big.Int
	Beta  *big.Int
}

func (params *BCECTSS_Params) hash(plain *big.Int) *big.Int {
	hash := sha256.New()
	hash.Write(plain.Bytes())

	var digest *big.Int
	digest.SetBytes(hash.Sum(nil))
	return digest.Mod(digest, params.Order)
}

func New(params *BCECTSS_Params, id *big.Int) *_BCECTSS {
	node := _BCECTSS{}
	node.id = id
	node.a = make([]*big.Int, params.Threshold)

	for i := 0; i < params.Threshold; i++ {
		node.a[i], _ = rand.Int(rand.Reader, params.Order.Sub(params.Order, big.NewInt(1)))
		node.a[i].Add(node.a[i], big.NewInt(1))
	}

	node.eta = make([]*elliptic_curve.Point, params.Threshold)
	for i := 0; i < params.Threshold; i++ {
		node.eta[i] = params.G.Multiply(node.a[i])
	}

	node.Params = params

	return &node
}

func (n *_BCECTSS) f(x *big.Int) *big.Int {
	res := big.NewInt(0)
	var temp *big.Int
	for i := 0; i < len(n.a); i++ {
		res.Add(res, temp.Mul(n.a[i], temp.Exp(x, big.NewInt(int64(i)), n.Params.Order)))
	}
	return res.Mod(res, n.Params.Order)
}

func (n *_BCECTSS) SecretShare(id_j *big.Int) *big.Int {
	return n.f(id_j)
}

func (n *_BCECTSS) VerifySecretShare(share *big.Int, etas []*elliptic_curve.Point) bool {
	rhs := make([]*elliptic_curve.Point, n.Params.Threshold)
	var temp *big.Int
	for i := 0; i < n.Params.Threshold; i++ {
		etas[i].Multiply(temp.Exp(n.id, big.NewInt(int64(i)), n.Params.Order))
	}
	rhsSum, _ := elliptic_curve.PointSum(rhs)

	return n.Params.G.Multiply(share).Equals(rhsSum)
}

func (n *_BCECTSS) SetPersonalKeys(shares []*big.Int) {
	n.sk = big.NewInt(0)
	for _, s := range shares {
		n.sk.Add(n.sk, s)
	}

	n.pk = n.Params.G.Multiply(n.sk)
}

func (n *_BCECTSS) SetSystemKey(eta0 []*elliptic_curve.Point) {
	n.Q = nil

	for _, eta := range eta0 {
		n.Q, _ = n.Q.Add(eta)
	}
}

func (n *_BCECTSS) chi(ids []*big.Int) *big.Int {
	chi := big.NewInt(1)
	var temp *big.Int
	for _, id := range ids {
		chi.Mul(chi, temp.Neg(id))
		chi.Mul(chi, temp.ModInverse(temp.Sub(n.id, id), n.Params.Order))
	}
	return chi.Mod(chi, n.Params.Order)
}

func (n *_BCECTSS) PartialSignature(message *big.Int, signers []*big.Int) *Signature {
	k, _ := rand.Int(rand.Reader, n.Params.Order.Sub(n.Params.Order, big.NewInt(1)))
	k.Add(k, big.NewInt(1))

	e := n.Params.hash(message)

	point := n.Params.G.Multiply(k)

	r := point.X.Mod(point.X, n.Params.Order)
	if r.Cmp(big.NewInt(0)) == 0 {
		r = big.NewInt(1)
	}

	beta, _ := rand.Int(rand.Reader, n.Params.Order.Sub(n.Params.Order, big.NewInt(1)))
	beta.Add(beta, big.NewInt(1))

	var temp *big.Int
	alpha := temp.Mul(temp.Sub(k, temp.Mul(beta, message)), temp.ModInverse(r, n.Params.Order))
	alpha.Mod(alpha, n.Params.Order)

	chi := n.chi(signers)
	l := temp.Mod(temp.Add(temp.Mul(alpha, r), temp.Mul(temp.Mul(e, chi), n.sk)), n.Params.Order)

	return &Signature{point, l, beta}
}

func (n *_BCECTSS) VerifyPartialSignature(message *big.Int, sig *Signature, signers []*big.Int) bool {
	var temp *big.Int
	gamma := temp.Mod(temp.Add(sig.L, temp.Mul(sig.Beta, message)), n.Params.Order)

	e := n.Params.hash(message)

	chi := n.chi(signers)
	point, _ := n.Params.G.Multiply(gamma).Add(n.pk.Multiply(e.Mul(e, chi)).Negate())

	return point.Equals(sig.Point)
}
