package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
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
func (circuit *Circuit) Define(curveID ecc.ID, api frontend.API) error {
	x3 := api.Mul(circuit.X, circuit.X, circuit.X)
	api.AssertIsEqual(circuit.Y, api.Add(x3, circuit.X, 5))
	return nil
}

func main() {
	var cubicCircuit Circuit
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &cubicCircuit)
	if err != nil {
		return
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		return
	}

	witness := &Circuit{
		X: frontend.Value(3),
		Y: frontend.Value(35),
	}
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		return
	}

	publicWitness := &Circuit{
		Y: frontend.Value(35),
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Printf("verification failed\n")
		return
	}
	fmt.Printf("verification succeded\n")
}
