package bc_ectss

import (
	"math/big"

	"github.com/jukuly/honours_project/internal/elliptic_curve"
	"github.com/jukuly/honours_project/internal/encryption"
)

type TestBCECTSSEncryption struct {
	Params       *encryption.ECC_Params
	Ids          []*big.Int
	Tag          *big.Int
	DecrypterIds []*big.Int
	parties      []*BCECTSS
}

func (sys *TestBCECTSSEncryption) Setup() {
	sys.parties = make([]*BCECTSS, len(sys.Ids))
	for i := range sys.parties {
		sys.parties[i] = New(sys.Params, sys.Ids[i])
	}

	// secret share from j to i
	secretShares := make([][]*big.Int, len(sys.Ids))
	eta0 := make([]*elliptic_curve.Point, len(sys.Ids))

	for i, p_i := range sys.parties {
		eta0[i] = p_i.Eta[0]
		secretShares[i] = make([]*big.Int, len(sys.Ids))
		for j, p_j := range sys.parties {
			secretShares[i][j] = p_j.SecretShare(p_i.Id)
		}
	}

	for i, p := range sys.parties {
		p.SetPersonalKeys(secretShares[i])
		p.SetSystemKey(eta0)
	}
}

func (sys *TestBCECTSSEncryption) Encrypt(plain *big.Int) any {
	plainPoint := sys.Params.G.Multiply(plain) // TODO put better map here
	cipher, _ := Encrypt(plainPoint, sys.Tag, sys.parties[0].Q, sys.Params)
	return cipher
}

func (sys *TestBCECTSSEncryption) Decrypt(cipher any) {
	partialSignatures := make([]*Signature, len(sys.DecrypterIds))
	for i := range partialSignatures {
		partialSignatures[i] = sys.parties[i].PartialSignature(sys.Tag, sys.DecrypterIds)
	}

	finalSignature, _ := sys.parties[0].CombineSignature(partialSignatures)

	Decrypt(cipher.(*Ciphertext), finalSignature)
}
