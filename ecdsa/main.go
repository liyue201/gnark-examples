package main

import (
	"github.com/consensys/gnark/frontend"
	"math/big"
)

const (
	N = 64
	K = 4
)

type ECDSAPrivToPubCircuit struct {
	PrivteKey [K]frontend.Variable    `gnark:"private_key,private"`
	PublicKey [2][K]frontend.Variable `gnark:"private_key,public"`
}

func (circuit *ECDSAPrivToPubCircuit) Define(api frontend.API) error {
	const stride = 8
	var n2b [K][]frontend.Variable
	for i := 0; i < K; i++ {
		n2b[i] = api.ToBinary(circuit.PrivteKey[i], N)
	}
	const numStrides = 64 * 4 / 8 //DivCel(N*K, stride)
	powers := GetGPowStride8Table()
	dummyHolder := GetDummyPoint(N, K)

	var dummy [2][K]big.Int
	for i := 0; i < K; i++ {
		dummy[0][i] = dummyHolder[0][i]
	}
	for i := 0; i < K; i++ {
		dummy[1][i] = dummyHolder[1][i]
	}

	// selector[i] contains a value in [0, ..., 2**i - 1]
	var selectors [numStrides][]frontend.Variable

	for i := 0; i < numStrides; i++ {
		selectors[i] = api.ToBinary(circuit.PrivteKey[i], stride)

		for j := 0; j < stride; j++ {
			bitIdx1 := (i*stride + j) / N
			bitIdx2 := (i*stride + j) % N
			selectors[i][j] = api.Select(bitIdx1 < K, n2b[bitIdx1][bitIdx2], 0)
		}
	}

	return nil
}

func main() {

}
