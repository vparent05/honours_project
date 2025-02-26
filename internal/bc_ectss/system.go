package bcectss

import (
	"math/big"

	"github.com/jukuly/honours_project/internal/elliptic_curve"
)

type System struct {
	curve     *elliptic_curve.EllipticCurve
	G         *elliptic_curve.Point
	q         *big.Int
	Users     []*node
	threshold int
	Q         *elliptic_curve.Point
}

var sys *System

func GetSystem() *System {
	if sys == nil {
		panic("System not initialized")
	}
	return sys
}

func (s *System) SetQ() *elliptic_curve.Point {
	s.Q = nil

	for _, user := range s.Users {
		s.Q, _ = s.Q.Add(user.eta[0])
	}

	return s.Q
}
