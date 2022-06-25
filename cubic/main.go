package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Circuit defines a simple circuit
// x**3 + x + 5 == y
type Circuit struct {
	// struct tags on a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:"x"`
	Y frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
// x**3 + x + 5 == y
func (circuit *Circuit) Define(api frontend.API) error {
	x3 := api.Mul(circuit.X, circuit.X, circuit.X)
	api.AssertIsEqual(circuit.Y, api.Add(x3, circuit.X, 5))
	return nil
}

func main() {
	curve := ecc.BN254
	r1cs, err := frontend.Compile(curve, r1cs.NewBuilder, &Circuit{})
	if err != nil {
		fmt.Printf("Compile failed\n")
		return
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Printf("Setup failed\n")
		return
	}

	validWitness, err := frontend.NewWitness(&Circuit{
		X: 3,
		Y: 35,
	}, curve)
	proof, err := groth16.Prove(r1cs, pk, validWitness)
	if err != nil {
		fmt.Printf("Prove failed： %v\n", err)
		return
	}

	validPublicWitness, err := frontend.NewWitness(&Circuit{
		Y: 35,
	}, curve, frontend.PublicOnly())

	err = groth16.Verify(proof, vk, validPublicWitness)
	if err != nil {
		fmt.Printf("verification failed\n")
		return
	}

	fmt.Printf("Verification successful\n")
}
