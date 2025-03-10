package threshold_elgamal

import (
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/jukuly/honours_project/internal/elliptic_curve"
	"github.com/jukuly/honours_project/internal/utils"
)

type Elgamal_Params struct {
	G         *elliptic_curve.Point
	Order     *big.Int
	Threshold int
}

type Ciphertext struct {
	c1 *elliptic_curve.Point
	c2 *elliptic_curve.Point
}

func (params *Elgamal_Params) chi(id_i *big.Int, ids []*big.Int) *big.Int {
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

func f(coefficients []*big.Int, order *big.Int, x *big.Int) *big.Int {
	res := big.NewInt(0)
	for i, coeff := range coefficients {
		res.Add(res, utils.PureMul(coeff, utils.PureExp(x, big.NewInt(int64(i)), order)))
	}

	return res.Mod(res, order)
}

func (params *Elgamal_Params) personalPublicKey(sk *big.Int) *elliptic_curve.Point {
	return params.G.Multiply(sk)
}

func (params *Elgamal_Params) GenerateKeys(ids []*big.Int) ([]*elliptic_curve.Point, []*big.Int, *elliptic_curve.Point) {
	coefficients := make([]*big.Int, params.Threshold)
	for i := range coefficients {
		coefficients[i], _ = rand.Int(rand.Reader, params.Order)
	}

	private := make([]*big.Int, len(ids))
	for i := range private {
		private[i] = f(coefficients, params.Order, ids[i])
	}

	public := make([]*elliptic_curve.Point, len(ids))
	for i := range public {
		public[i] = params.personalPublicKey(private[i])
	}

	globalPublic := make([]*elliptic_curve.Point, len(ids))
	for i := range globalPublic {
		globalPublic[i] = public[i].Multiply(params.chi(ids[i], ids))
	}

	globalPublicSum, _ := elliptic_curve.PointSum(globalPublic)

	return public, private, globalPublicSum
}

func (params *Elgamal_Params) Encrypt(plaintext *elliptic_curve.Point, publicKey *elliptic_curve.Point) (*Ciphertext, error) {
	alpha, _ := rand.Int(rand.Reader, params.Order)

	c1 := params.G.Multiply(alpha)
	c2, err := publicKey.Multiply(alpha).Add(plaintext)
	if err != nil {
		return nil, errors.New("plaintext is not on the system curve")
	}

	return &Ciphertext{c1, c2}, nil
}

func PartialDecrypt(cipher *Ciphertext, sk *big.Int) *elliptic_curve.Point {
	return cipher.c1.Multiply(sk)
}

func (params *Elgamal_Params) Decrypt(shares []*elliptic_curve.Point, cipher *Ciphertext, parties []*big.Int) (*elliptic_curve.Point, error) {
	c1_prime := make([]*elliptic_curve.Point, len(parties))
	for i := range parties {
		c1_prime[i] = shares[i].Multiply(params.chi(parties[i], parties))
	}
	c1_prime_sum, err := elliptic_curve.PointSum(c1_prime)
	if err != nil {
		return nil, errors.New("invalid shares")
	}

	return cipher.c2.Add(c1_prime_sum.Negate())
}
