package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
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
func (circuit *Circuit) Define(curveID ecc.ID, api frontend.API) error {
	// number of bits of exponent
	const bitSize = 8

	// specify constraints
	output := api.Constant(1)
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
	var expCircuit Circuit
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &expCircuit)
	if err != nil {
		fmt.Printf("Compile failed : %v\n", err)
		return
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Printf("Setup failed\n")
		return
	}

	witness := &Circuit{
		X: frontend.Value(3),
		Y: frontend.Value(59049),
		E: frontend.Value(10),
	}
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Printf("Prove failed： %v\n", err)
		return
	}

	publicWitness := &Circuit{
		X: frontend.Value(3),
		Y: frontend.Value(59049),
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Printf("verification failed: %v\n", err)
		return
	}
	fmt.Printf("verification succeded\n")
}
