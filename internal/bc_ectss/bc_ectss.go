package bc_ectss

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/jukuly/honours_project/internal/elliptic_curve"
	"github.com/jukuly/honours_project/internal/utils"
)

type BCECTSS_Params struct {
	G         *elliptic_curve.Point
	Order     *big.Int
	Threshold int
}

type BCECTSS struct {
	Id     *big.Int
	a      []*big.Int
	Eta    []*elliptic_curve.Point
	sk     *big.Int
	Pk     *elliptic_curve.Point
	Q      *elliptic_curve.Point
	Params *BCECTSS_Params
}

type Signature struct {
	Point *elliptic_curve.Point
	L     *big.Int
	Beta  *big.Int
}

type Ciphertext struct {
	c1 *elliptic_curve.Point
	c2 *big.Int
	c3 *elliptic_curve.Point
	c4 *elliptic_curve.Point
}

func (params *BCECTSS_Params) hash(plain *big.Int) *big.Int {
	hash := sha256.New()
	hash.Write(plain.Bytes())

	digest := new(big.Int)
	digest.SetBytes(hash.Sum(nil))
	return digest.Mod(digest, params.Order)
}

func New(params *BCECTSS_Params, id *big.Int) *BCECTSS {
	node := new(BCECTSS)
	node.Id = id
	node.a = make([]*big.Int, params.Threshold)

	for i := range params.Threshold {
		node.a[i], _ = rand.Int(rand.Reader, utils.PureSub(params.Order, big.NewInt(1)))
		node.a[i].Add(node.a[i], big.NewInt(1))

	}

	node.Eta = make([]*elliptic_curve.Point, params.Threshold)
	for i := range params.Threshold {
		node.Eta[i] = params.G.Multiply(node.a[i])
	}

	node.Params = params
	return node
}

func (n *BCECTSS) f(x *big.Int) *big.Int {
	res := big.NewInt(0)
	for i, coeff := range n.a {
		res.Add(res, utils.PureMul(coeff, utils.PureExp(x, big.NewInt(int64(i)), n.Params.Order)))
	}

	return res.Mod(res, n.Params.Order)
}

func (n *BCECTSS) SecretShare(id_j *big.Int) *big.Int {
	return n.f(id_j)
}

func (n *BCECTSS) VerifySecretShare(share *big.Int, etas []*elliptic_curve.Point) bool {
	rhs := make([]*elliptic_curve.Point, n.Params.Threshold)
	for i := range n.Params.Threshold {
		rhs[i] = etas[i].Multiply(utils.PureExp(n.Id, big.NewInt(int64(i)), nil))
	}
	rhsSum, _ := elliptic_curve.PointSum(rhs)

	return n.Params.G.Multiply(share).Equals(rhsSum)
}

func (n *BCECTSS) SetPersonalKeys(shares []*big.Int) {
	n.sk = big.NewInt(0)
	for _, s := range shares {
		n.sk.Add(n.sk, s)
	}

	n.Pk = n.Params.G.Multiply(n.sk)
}

func (n *BCECTSS) SetSystemKey(eta0 []*elliptic_curve.Point) {
	n.Q = elliptic_curve.Infinity

	for _, eta := range eta0 {
		n.Q, _ = n.Q.Add(eta)
	}
}

func (params *BCECTSS_Params) chi(id_i *big.Int, ids []*big.Int) *big.Int {
	chi := big.NewInt(1)
	for _, id := range ids {
		if id.Cmp(id_i) == 0 {
			continue
		}
		chi.Mul(chi, utils.PureNeg(id))
		chi.Mul(chi, utils.PureModInverse(utils.PureSub(id_i, id), params.Order))
	}
	return chi.Mod(chi, params.Order)
}

func (n *BCECTSS) PartialSignature(message *big.Int, signers []*big.Int) *Signature {
	k, _ := rand.Int(rand.Reader, utils.PureSub(n.Params.Order, big.NewInt(1)))
	k.Add(k, big.NewInt(1))

	e := n.Params.hash(message)

	point := n.Params.G.Multiply(k)

	r := point.X.Mod(point.X, n.Params.Order)
	if r.Cmp(big.NewInt(0)) == 0 {
		r = big.NewInt(1)
	}

	beta, _ := rand.Int(rand.Reader, utils.PureSub(n.Params.Order, big.NewInt(1)))
	beta.Add(beta, big.NewInt(1))
	alpha := utils.PureMul(utils.PureSub(k, utils.PureMul(beta, message)), utils.PureModInverse(r, n.Params.Order))
	alpha.Mod(alpha, n.Params.Order)

	chi := n.Params.chi(n.Id, signers)
	l := utils.PureMod(utils.PureAdd(utils.PureMul(alpha, r), utils.PureMul(utils.PureMul(e, chi), n.sk)), n.Params.Order)

	return &Signature{point, l, beta}
}

func (n *BCECTSS) VerifyPartialSignature(message *big.Int, sig *Signature, pk *elliptic_curve.Point, id *big.Int, signers []*big.Int) bool {
	gamma := utils.PureMod(utils.PureAdd(sig.L, utils.PureMul(sig.Beta, message)), n.Params.Order)

	e := n.Params.hash(message)

	chi := n.Params.chi(id, signers)
	point, _ := n.Params.G.Multiply(gamma).Add(pk.Multiply(e.Mul(e, chi)).Negate())

	return point.Equals(sig.Point)
}

func (n *BCECTSS) CombineSignature(partialSignatures []*Signature) (*Signature, error) {
	l := big.NewInt(0)
	beta := big.NewInt(0)
	point := elliptic_curve.Infinity

	var err error
	for _, sig := range partialSignatures {
		l.Mod(l.Add(l, sig.L), n.Params.Order)
		beta.Mod(beta.Add(beta, sig.Beta), n.Params.Order)
		point, err = point.Add(sig.Point)
		if err != nil {
			return nil, errors.New("invalid partial signatures")
		}
	}

	return &Signature{point, l, beta}, nil
}

func (n *BCECTSS) VerifySignature(message *big.Int, sig *Signature) bool {
	gamma := utils.PureMod(utils.PureAdd(sig.L, utils.PureMul(sig.Beta, message)), n.Params.Order)

	e := n.Params.hash(message)
	point, _ := n.Params.G.Multiply(gamma).Add(n.Q.Multiply(e).Negate())

	return point.Equals(sig.Point)
}

func (params *BCECTSS_Params) Encrypt(plaintext *elliptic_curve.Point, tag *big.Int, Q *elliptic_curve.Point) (*Ciphertext, error) {
	alpha, _ := rand.Int(rand.Reader, params.Order)

	e := params.hash(tag)

	c1, err := Q.Multiply(utils.PureMul(alpha, e)).Add(plaintext)
	if err != nil {
		return nil, errors.New("plaintext is not on the system curve")
	}

	c2 := utils.PureNeg(alpha)
	c3 := params.G.Multiply(alpha)
	c4 := c3.Multiply(e)

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
