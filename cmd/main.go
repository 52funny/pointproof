package main

import (
	"fmt"

	"github.com/52funny/pointproof"
	"github.com/cloudflare/circl/ecc/bls12381"
)

func main() {
	pp := pointproof.Setup(2)

	for i := range pp.P1 {
		fmt.Println(pp.P1[i].String())
		fmt.Println()
	}

	fmt.Println()
	for i := range pp.P2 {
		fmt.Println(pp.P2[i].String())
		fmt.Println()
	}

	messages := []string{"hello", "world"}
	messagesScalar := pointproof.MessageToScalar(messages)

	c := pp.Commitment(messagesScalar)
	fmt.Println("Commitment:")
	fmt.Println(c.String())
	fmt.Println()

	proof := pp.Proof(messagesScalar, 1)
	fmt.Println("Proof:")
	fmt.Println(proof.String())
	fmt.Println()

	aggProof := pp.Aggregate(c, []int{1}, messagesScalar[1:], []*bls12381.G1{proof})

	fmt.Println("Aggregate Proof:")
	fmt.Println(aggProof.String())
	fmt.Println()
	ret := pp.Verify(c, []int{1}, messagesScalar[1:], aggProof)
	fmt.Println("Verify:", ret)

	changed := []string{"hello", "!"}
	changeScalar := pointproof.MessageToScalar(changed)

	cUpdate := pp.UpdateCommitment(c, pointproof.MessageToScalar([]string{"world"}), changeScalar[1:], []int{1})

	fmt.Println("Update Commitment:")
	fmt.Println(cUpdate.String())
	fmt.Println()

	proof2 := pp.Proof(changeScalar, 1)

	aggProof2 := pp.Aggregate(cUpdate, []int{1}, changeScalar[1:], []*bls12381.G1{proof2})

	ret2 := pp.Verify(cUpdate, []int{1}, changeScalar[1:], aggProof2)
	fmt.Println("Verify:", ret2)

}
