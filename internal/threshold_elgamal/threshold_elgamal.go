package threshold_elgamal

import (
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/jukuly/honours_project/internal/elliptic_curve"
	"github.com/jukuly/honours_project/internal/encryption"
	"github.com/jukuly/honours_project/internal/utils"
)

type Ciphertext struct {
	c1 *elliptic_curve.Point
	c2 *elliptic_curve.Point
}

func f(coefficients []*big.Int, order *big.Int, x *big.Int) *big.Int {
	res := big.NewInt(0)
	for i, coeff := range coefficients {
		res.Add(res, utils.PureMul(coeff, utils.PureExp(x, big.NewInt(int64(i)), order)))
	}

	return res.Mod(res, order)
}

func personalPublicKey(sk *big.Int, params *encryption.ECC_Params) *elliptic_curve.Point {
	return params.G.Multiply(sk)
}

func GenerateKeys(ids []*big.Int, params *encryption.ECC_Params) ([]*elliptic_curve.Point, []*big.Int, *elliptic_curve.Point) {
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
		public[i] = personalPublicKey(private[i], params)
	}

	globalPublic := make([]*elliptic_curve.Point, len(ids))
	for i := range globalPublic {
		globalPublic[i] = public[i].Multiply(utils.Chi(ids[i], ids, params.Order))
	}

	globalPublicSum, _ := elliptic_curve.PointSum(globalPublic)

	return public, private, globalPublicSum
}

func Encrypt(plaintext *elliptic_curve.Point, publicKey *elliptic_curve.Point, params *encryption.ECC_Params) (*Ciphertext, error) {
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

func Decrypt(shares []*elliptic_curve.Point, cipher *Ciphertext, parties []*big.Int, params *encryption.ECC_Params) (*elliptic_curve.Point, error) {
	c1_prime := make([]*elliptic_curve.Point, len(parties))
	for i := range parties {
		c1_prime[i] = shares[i].Multiply(utils.Chi(parties[i], parties, params.Order))
	}
	c1_prime_sum, err := elliptic_curve.PointSum(c1_prime)
	if err != nil {
		return nil, errors.New("invalid shares")
	}

	return cipher.c2.Add(c1_prime_sum.Negate())
}
