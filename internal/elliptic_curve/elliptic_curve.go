package ellipticcurve

import (
	"fmt"

	"github.com/jukuly/honours_project/internal/utils"
)

// Use nil to represent the point at infinity
type point struct {
	X     int
	Y     int
	curve *EllipticCurve
}

// y^2 = x^3 + ax + b (mod p)
type EllipticCurve struct {
	A int
	B int
	P int
}

func (pt *point) Equals(other *point) bool {
	return pt.X == other.X && pt.Y == other.Y && pt.curve == other.curve
}

func (ec *EllipticCurve) Point(x, y int) (*point, error) {
	if y*y != x*x*x+ec.A*x+ec.B {
		return nil, fmt.Errorf("point (%d, %d) is not on the curve", x, y)
	}

	return &point{x % ec.P, y % ec.P, ec}, nil
}

func (pt *point) Add(other *point) (*point, error) {
	if pt.curve != other.curve {
		return nil, fmt.Errorf("points are not on the same curve")
	}
	if pt == nil {
		return other, nil
	}
	if other == nil {
		return pt, nil
	}

	if pt.X == other.X && (pt.Y != other.Y || pt.Y == 0) {
		return nil, nil
	}

	var m int
	if pt.Equals(other) {
		m = (3*pt.X*pt.X + pt.curve.A) * utils.Inverse(2*pt.Y, pt.curve.P) % pt.curve.P
	} else {
		m = (other.Y - pt.Y) * utils.Inverse(other.X-pt.X, pt.curve.P) % pt.curve.P
	}

	x := m*m - pt.X - other.X
	y := m*(pt.X-x) - pt.Y

	return pt.curve.Point(x, y)
}

func (pt *point) Negate() *point {
	res, _ := pt.curve.Point(pt.X, -pt.Y)
	return res
}

func (pt *point) Multiply(n int) *point {
	var Q *point = nil

	R := pt
	if n < 0 {
		R = R.Negate()
		n = -n
	}

	for n > 0 {
		if n%2 == 1 {
			Q, _ = Q.Add(R)
		}
		R, _ = R.Add(R)
		n /= 2
	}

	return Q
}
