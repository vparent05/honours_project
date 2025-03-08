package elliptic_curve

import (
	"errors"
	"math/big"

	"github.com/jukuly/honours_project/internal/utils"
)

// Use infinity = true to represent the point at infinity
type Point struct {
	X        *big.Int
	Y        *big.Int
	curve    *EllipticCurve
	infinity bool
}

var Infinity = &Point{nil, nil, nil, true}

// y^2 = x^3 + ax + b (mod p)
type EllipticCurve struct {
	A *big.Int
	B *big.Int
	P *big.Int
}

func (pt *Point) Equals(other *Point) bool {
	if pt.infinity {
		return other.infinity
	}
	return pt.X.Cmp(other.X) == 0 && pt.Y.Cmp(other.Y) == 0 && pt.curve == other.curve
}

func (ec *EllipticCurve) Point(x, y *big.Int) (*Point, error) {
	if utils.PureExp(y, big.NewInt(2), ec.P).Cmp(utils.PureAdd(utils.PureAdd(utils.PureExp(x, big.NewInt(3), ec.P), utils.PureMul(ec.A, x)), ec.B)) != 0 {
		return nil, errors.New("point is not on the curve")
	}

	return &Point{x.Mod(x, ec.P), y.Mod(y, ec.P), ec, false}, nil
}

func (pt *Point) Add(other *Point) (*Point, error) {
	if pt.infinity {
		return other, nil
	}
	if other.infinity {
		return pt, nil
	}
	if pt.curve != other.curve {
		return nil, errors.New("points are not on the same curve")
	}

	if pt.X.Cmp(other.X) == 0 && (pt.Y.Cmp(other.Y) != 0 || pt.Y.Cmp(big.NewInt(0)) == 0) {
		return Infinity, nil
	}

	m := new(big.Int)
	if pt.Equals(other) {
		m = utils.PureMod(
			utils.PureMul(
				utils.PureAdd(
					utils.PureMul(
						big.NewInt(3),
						utils.PureExp(pt.X, big.NewInt(2), pt.curve.P)),
					pt.curve.A),
				utils.PureModInverse(utils.PureMul(big.NewInt(2), pt.Y), pt.curve.P)),
			pt.curve.P)
	} else {
		m = utils.PureMod(
			utils.PureMul(
				utils.PureSub(other.Y, pt.Y),
				utils.PureModInverse(utils.PureSub(other.X, pt.X), pt.curve.P)),
			pt.curve.P)
	}

	x := utils.PureSub(utils.PureExp(m, big.NewInt(2), pt.curve.P), utils.PureAdd(pt.X, other.X))
	y := utils.PureSub(utils.PureMul(m, utils.PureSub(pt.X, x)), pt.Y)

	return pt.curve.Point(x, y)
}

func (pt *Point) Negate() *Point {
	if pt.infinity {
		return pt
	}
	res, _ := pt.curve.Point(pt.X, pt.Y.Neg(pt.Y))
	return res
}

func (pt *Point) Multiply(n *big.Int) *Point {
	Q := Infinity

	n_copy := new(big.Int)
	n_copy.SetBytes(n.Bytes())

	R := pt
	if n_copy.Cmp(big.NewInt(0)) == -1 {
		R.Negate()
		n_copy.Neg(n_copy)
	}

	for n_copy.Cmp(big.NewInt(0)) == 1 {
		if utils.PureMod(n_copy, big.NewInt(2)).Int64() == 1 {
			Q, _ = Q.Add(R)
		}
		R, _ = R.Add(R)
		n_copy.Div(n_copy, big.NewInt(2))
	}

	return Q
}

func PointSum(points []*Point) (*Point, error) {
	sum := Infinity
	var err error
	for _, pt := range points {
		sum, err = sum.Add(pt)
		if err != nil {
			return nil, err
		}
	}
	return sum, nil
}
