package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
	"math/big"
)

type Circuit struct {
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	mimc, _ := mimc.NewMiMC(api)
	// specify constraints
	// mimc(preImage) == hash
	mimc.Write(circuit.PreImage)
	api.AssertIsEqual(circuit.Hash, mimc.Sum())
	return nil
}

func mimcHash(data []byte) string {
	f := bn254.NewMiMC()
	f.Write(data)
	hash := f.Sum(nil)
	hashInt := big.NewInt(0).SetBytes(hash)
	return hashInt.String()
}

func main() {
	preImage := []byte{0x01, 0x02, 0x03}
	hash := mimcHash(preImage)

	fmt.Printf("hash: %s\n", hash)

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
		PreImage: preImage,
		Hash:     hash,
	}, curve)

	proof, err := groth16.Prove(r1cs, pk, validWitness)
	if err != nil {
		fmt.Printf("Prove failed： %v\n", err)
		return
	}

	validPublicWitness, err := frontend.NewWitness(&Circuit{
		Hash: hash,
	}, curve, frontend.PublicOnly())

	err = groth16.Verify(proof, vk, validPublicWitness)
	if err != nil {
		fmt.Printf("verification failed: %v\n", err)
		return
	}
	fmt.Printf("Verification successful\n")
}
