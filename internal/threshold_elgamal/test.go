package threshold_elgamal

import (
	"math/big"

	"github.com/jukuly/honours_project/internal/elliptic_curve"
	"github.com/jukuly/honours_project/internal/encryption"
)

type TestElgamalEncryption struct {
	Params       *encryption.ECC_Params
	Ids          []*big.Int
	DecrypterIds []*big.Int
	private      []*big.Int
	global       *elliptic_curve.Point
}

func (sys *TestElgamalEncryption) Setup() {
	_, sys.private, sys.global = GenerateKeys(sys.Ids, sys.Params)
}

func (sys *TestElgamalEncryption) Encrypt(plain *big.Int) any {
	plainPoint := sys.Params.G.Multiply(plain) // TODO put better map here
	cipher, _ := Encrypt(plainPoint, sys.global, sys.Params)
	return cipher
}

func (sys *TestElgamalEncryption) Decrypt(cipher any) {
	shares := make([]*elliptic_curve.Point, len(sys.DecrypterIds))
	for i := range shares {
		shares[i] = PartialDecrypt(cipher.(*Ciphertext), sys.private[i])
	}

	Decrypt(shares, cipher.(*Ciphertext), sys.DecrypterIds, sys.Params)
}
