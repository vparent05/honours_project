package elliptic_curve

import (
	"fmt"
	"math/big"
)

// Use nil to represent the point at infinity
type Point struct {
	X     *big.Int
	Y     *big.Int
	curve *EllipticCurve
}

// y^2 = x^3 + ax + b (mod p)
type EllipticCurve struct {
	A *big.Int
	B *big.Int
	P *big.Int
}

func (pt *Point) Equals(other *Point) bool {
	return pt.X.Cmp(other.X) == 0 && pt.Y.Cmp(other.Y) == 0 && pt.curve == other.curve
}

func (ec *EllipticCurve) Point(x, y *big.Int) (*Point, error) {
	var temp big.Int
	if temp.Exp(y, big.NewInt(2), ec.P) != temp.Add(temp.Add(temp.Exp(x, big.NewInt(3), ec.P), temp.Mul(ec.A, x)), ec.B) {
		return nil, fmt.Errorf("point (%d, %d) is not on the curve", x, y)
	}

	return &Point{x.Mod(x, ec.P), y.Mod(y, ec.P), ec}, nil
}

func (pt *Point) Add(other *Point) (*Point, error) {
	if pt.curve != other.curve {
		return nil, fmt.Errorf("points are not on the same curve")
	}
	if pt == nil {
		return other, nil
	}
	if other == nil {
		return pt, nil
	}

	if pt.X.Cmp(other.X) == 0 && (pt.Y.Cmp(other.Y) != 0 || pt.Y.Cmp(big.NewInt(0)) == 0) {
		return nil, nil
	}

	var m *big.Int
	var temp *big.Int
	if pt.Equals(other) {
		m = temp.Mod(
			temp.Mul(
				temp.Mul(
					big.NewInt(3),
					temp.Exp(pt.X, big.NewInt(2), pt.curve.P)),
				temp.ModInverse(temp.Mul(big.NewInt(2), pt.Y), pt.curve.P)),
			pt.curve.P)
	} else {
		m = temp.Mod(
			temp.Mul(
				temp.Sub(other.Y, pt.Y),
				temp.ModInverse(temp.Sub(other.X, pt.X), pt.curve.P)),
			pt.curve.P)
	}

	x := temp.Sub(temp.Exp(m, big.NewInt(2), pt.curve.P), temp.Add(pt.X, other.X))
	y := temp.Sub(temp.Mul(m, temp.Sub(pt.X, x)), pt.Y)

	return pt.curve.Point(x, y)
}

func (pt *Point) Negate() *Point {
	res, _ := pt.curve.Point(pt.X, pt.Y.Neg(pt.Y))
	return res
}

func (pt *Point) Multiply(n *big.Int) *Point {
	var Q *Point = nil

	R := pt
	if n.Cmp(big.NewInt(0)) == -1 {
		R.Negate()
		n.Neg(n)
	}

	var temp *big.Int
	for n.Cmp(big.NewInt(0)) == 1 {
		if temp.Mod(n, big.NewInt(2)).Int64() == 1 {
			Q, _ = Q.Add(R)
		}
		R, _ = R.Add(R)
		n.Div(n, big.NewInt(2))
	}

	return Q
}

func PointSum(points []*Point) (*Point, error) {
	var sum *Point
	var err error
	for _, pt := range points {
		sum, err = sum.Add(pt)
		if err != nil {
			return nil, err
		}
	}
	return sum, nil
}
