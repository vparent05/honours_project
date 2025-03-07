package crypto

import "math/big"

type System interface {
	NewNode() *Node
	Setup()
	GetSignature() any
	VerifySignature(*big.Int, any) bool
	Encrypt()
	Decrypt()
}

type Node interface {
	GetPartialSignature()
	VerifyPartialSignature()
}
