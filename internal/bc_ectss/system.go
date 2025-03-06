package bc_ectss

import (
	"crypto/sha256"
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

var sys *System

func SetSystem(newSys *System) {
	sys = newSys
}

func GetSystem() *System {
	if sys == nil {
		panic("System not initialized")
	}
	return sys
}

func Hash(plain *big.Int) *big.Int {
	hash := sha256.New()
	hash.Write(plain.Bytes())

	var digest *big.Int
	digest.SetBytes(hash.Sum(nil))
	return digest.Mod(digest, GetSystem().Order)
}

func (s *System) SetPublicKey() *elliptic_curve.Point {
	s.PublicKey = nil

	for _, user := range s.Users {
		s.PublicKey, _ = s.PublicKey.Add(user.eta[0])
	}

	return s.PublicKey
}
