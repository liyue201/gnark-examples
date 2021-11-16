package main

import (
	"bytes"
	"fmt"
	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/hash/mimc"
	"math/rand"
	"time"
)

type merkleCircuit struct {
	RootHash     frontend.Variable `gnark:",public"`
	Path, Helper []frontend.Variable
}

func (circuit *merkleCircuit) Define(curveID ecc.ID, api frontend.API) error {
	hFunc, err := mimc.NewMiMC("seed", curveID, api)
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
	merkleRoot, merkleProof, numLeaves, err := merkletree.BuildReaderProof(&buf, bn254.NewMiMC("seed"), segmentSize, proofIndex)
	if err != nil {
		return
	}
	//fmt.Printf("numLeaves: %v\n", numLeaves)
	//fmt.Printf("proof: %v\n", len(merkleProof))

	proofHelper := merkle.GenerateProofHelper(merkleProof, proofIndex, numLeaves)

	fmt.Printf("proofHelper: %v\n", proofHelper)

	verified := merkletree.VerifyProof(bn254.NewMiMC("seed"), merkleRoot, merkleProof, proofIndex, numLeaves)
	if !verified {
		fmt.Printf("The merkle proof in plain go should pass")
	}

	// create cs
	circuit := merkleCircuit{
		Path:   make([]frontend.Variable, len(merkleProof)),
		Helper: make([]frontend.Variable, len(merkleProof)-1),
	}
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		fmt.Printf("Compile failed : %v\n", err)
		return
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Printf("Setup failed\n")
		return
	}

	witness := &merkleCircuit{
		Path:     make([]frontend.Variable, len(merkleProof)),
		Helper:   make([]frontend.Variable, len(merkleProof)-1),
		RootHash: frontend.Value(merkleRoot),
	}
	for i := 0; i < len(merkleProof); i++ {
		witness.Path[i].Assign(merkleProof[i])
	}
	for i := 0; i < len(merkleProof)-1; i++ {
		witness.Helper[i].Assign(proofHelper[i])
	}

	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Printf("Prove failed： %v\n", err)
		return
	}

	publicWitness := &merkleCircuit{
		RootHash: frontend.Value(merkleRoot),
	}
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Printf("verification failed: %v\n", err)
		return
	}
	fmt.Printf("verification succeded\n")
}
