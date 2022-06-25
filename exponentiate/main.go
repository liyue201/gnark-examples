package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Circuit y == x**e
// only the bitSize least significant bits of e are used
type Circuit struct {
	// tagging a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`

	E frontend.Variable
}

// Define declares the circuit's constraints
// y == x**e
func (circuit *Circuit) Define(api frontend.API) error {
	// number of bits of exponent
	const bitSize = 8

	// specify constraints
	output := frontend.Variable(1)
	bits := api.ToBinary(circuit.E, bitSize)
	multiply := circuit.X

	for i := 0; i < len(bits); i++ {
		//api.Println(fmt.Sprintf("e[%d]", i), bits[i]) // we may print a variable for testing and / or debugging purposes
		output = api.Select(bits[i], api.Mul(output, multiply), output)
		multiply = api.Mul(multiply, multiply)
	}
	api.AssertIsEqual(circuit.Y, output)

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
		Y: 59049,
		E: 10,
	}, curve)

	proof, err := groth16.Prove(r1cs, pk, validWitness)
	if err != nil {
		fmt.Printf("Prove failed： %v\n", err)
		return
	}

	validPublicWitness, err := frontend.NewWitness( &Circuit{
		X: 3,
		Y: 59049,
	}, curve, frontend.PublicOnly())

	err = groth16.Verify(proof, vk, validPublicWitness)
	if err != nil {
		fmt.Printf("verification failed: %v\n", err)
		return
	}
	fmt.Printf("Verification successful\n")
}
