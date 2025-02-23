package utils

// Find the inverse of b mod a
// Using the Extended Euclidean Algorithm
// It does not check if b has an inverse mod a
func Inverse(b, a int) int {
	q := a / b
	r := a % b
	s1 := 1
	s2 := 0
	s3 := 1
	t1 := 0
	t2 := 1
	t3 := -q

	for r != 0 {
		s1, s2, s3 = s2, s3, s1-q*s2
		t1, t2, t3 = t2, t3, t1-q*t2
		a, b = b, r
		q = a / b
		r = a % b
	}

	return t2 % a
}
