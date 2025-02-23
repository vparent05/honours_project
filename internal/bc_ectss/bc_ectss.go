package bcectss

import (
	"math/big"

	"github.com/jukuly/honours_project/internal/elliptic_curve"
)

type System struct {
	curve     *elliptic_curve.EllipticCurve
	G         *elliptic_curve.Point
	q         *big.Int
	Users     [][]int
	threshold int
	Q         *elliptic_curve.Point
}

type node struct {
	id int
	a  []*big.Int
	sk *big.Int
	pk *elliptic_curve.Point
}

func (sys *System) NewNode(id int) *node {
	return &node{id: id}
}
