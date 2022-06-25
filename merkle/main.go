package main

import (
	"bytes"
	"fmt"
	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/hash/mimc"
	"math/rand"
	"time"
)

type merkleCircuit struct {
	RootHash     frontend.Variable `gnark:",public"`
	Path, Helper []frontend.Variable
}

func (circuit *merkleCircuit) Define(api frontend.API) error {
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	merkle.VerifyProof(api, hFunc, circuit.RootHash, circuit.Path, circuit.Helper)
	return nil
}

func randomStr(length int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	bytes := []byte(str)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < length; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}

func main() {
	var buf bytes.Buffer
	for i := 0; i < 10; i++ {
		buf.Write([]byte(randomStr(10)))
	}

	// build & verify proof for an elmt in the file
	proofIndex := uint64(5)
	segmentSize := 10
	merkleRoot, merkleProof, numLeaves, err := merkletree.BuildReaderProof(&buf, bn254.NewMiMC(), segmentSize, proofIndex)
	if err != nil {
		return
	}
	//fmt.Printf("numLeaves: %v\n", numLeaves)
	//fmt.Printf("proof: %v\n", len(merkleProof))

	proofHelper := merkle.GenerateProofHelper(merkleProof, proofIndex, numLeaves)

	fmt.Printf("proofHelper: %v\n", proofHelper)

	verified := merkletree.VerifyProof(bn254.NewMiMC(), merkleRoot, merkleProof, proofIndex, numLeaves)
	if !verified {
		fmt.Printf("The merkle proof in plain go should pass")
	}

	// create cs
	circuit := merkleCircuit{
		Path:   make([]frontend.Variable, len(merkleProof)),
		Helper: make([]frontend.Variable, len(merkleProof)-1),
	}
	curve := ecc.BN254
	r1cs, err := frontend.Compile(curve, r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Printf("Compile failed\n")
		return
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Printf("Setup failed\n")
		return
	}

	witness := merkleCircuit{
		Path:     make([]frontend.Variable, len(merkleProof)),
		Helper:   make([]frontend.Variable, len(merkleProof)-1),
		RootHash: merkleRoot,
	}
	for i := 0; i < len(merkleProof); i++ {
		witness.Path[i] = merkleProof[i]
	}
	for i := 0; i < len(merkleProof)-1; i++ {
		witness.Helper[i] = proofHelper[i]
	}
	validWitness, err := frontend.NewWitness(&witness, curve)

	proof, err := groth16.Prove(r1cs, pk, validWitness)
	if err != nil {
		fmt.Printf("Prove failed： %v\n", err)
		return
	}

	validPublicWitness, err := frontend.NewWitness(&merkleCircuit{
		RootHash: merkleRoot,
	}, curve, frontend.PublicOnly())

	err = groth16.Verify(proof, vk, validPublicWitness)
	if err != nil {
		fmt.Printf("verification failed: %v\n", err)
		return
	}
	fmt.Printf("Verification successful\n")
}
