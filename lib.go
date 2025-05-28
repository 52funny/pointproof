package pointproof

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	"github.com/cloudflare/circl/ecc/bls12381"
)

type Pointproof struct {
	PP
}

type PP struct {
	N  int
	P1 []bls12381.G1
	P2 []bls12381.G2
}

// Setup returns the instance of the pointproof
func Setup(N int) *Pointproof {
	g1 := bls12381.G1Generator()
	g2 := bls12381.G2Generator()

	// g^alpha, g^alpha^2, ..., g^alpha^N, g^alpha^N+2, ..., g^alpha^2N
	p1 := make([]bls12381.G1, 2*N)
	p2 := make([]bls12381.G2, N)

	// secret alpha
	alpha := new(bls12381.Scalar)
	alpha.Random(rand.Reader)

	t := new(bls12381.Scalar)
	t.Set(alpha)

	for i := range N {
		p1[i].ScalarMult(t, g1)
		p2[i].ScalarMult(t, g2)
		t.Mul(t, alpha)
	}

	// skip g^alpha^N+1, current is g^alpha^N+2
	t.Mul(t, alpha)

	for i := N + 1; i < 2*N; i++ {
		p1[i].ScalarMult(t, g1)
		t.Mul(t, alpha)
	}

	return &Pointproof{
		PP: PP{N: N, P1: p1, P2: p2},
	}
}

// Give the message vector, return the commitment of the message vector
func (pp *Pointproof) Commitment(message []bls12381.Scalar) *bls12381.G1 {
	// set c is identity
	c := new(bls12381.G1)
	c.SetIdentity()

	for i := range message {
		t := new(bls12381.G1)
		t.ScalarMult(&message[i], &pp.P1[i])
		c.Add(c, t)
	}
	return c
}

// Update the message in the vector and return the new commitment
func (pp *Pointproof) UpdateCommitment(c *bls12381.G1, originMessage []bls12381.Scalar, nowMessage []bls12381.Scalar, sets []int) *bls12381.G1 {
	if len(originMessage) != len(nowMessage) {
		panic("originMessage and nowMessage must have the same length")
	}
	ret := new(bls12381.G1)
	ret.SetBytes(c.Bytes())

	sum := new(bls12381.G1)
	sum.SetIdentity()

	for i, s := range sets {
		sub := new(bls12381.Scalar)
		sub.Sub(&nowMessage[i], &originMessage[i])
		t := new(bls12381.G1)
		t.ScalarMult(sub, &pp.P1[s])
		sum.Add(sum, t)
	}
	ret.Add(ret, sum)
	return ret
}

// Proof returns the proof of the message at index i.
func (pp *Pointproof) Proof(message []bls12381.Scalar, i int) *bls12381.G1 {
	if i < 0 || i >= len(message) {
		panic("index out of range")
	}

	sum := new(bls12381.G1)
	sum.SetIdentity()

	for j := range message {
		// skip the index of i
		if j == i {
			continue
		}
		t := new(bls12381.G1)
		t.ScalarMult(&message[j], &pp.P1[pp.N-i+j])
		sum.Add(sum, t)
	}
	return sum
}

// Aggregate returns the aggregate proof
func (pp *Pointproof) Aggregate(c *bls12381.G1, sets []int, message []bls12381.Scalar, proofs []*bls12381.G1) *bls12381.G1 {
	if len(sets) != len(proofs) || len(sets) != len(message) {
		panic("sets, message and proofs must have the same length")
	}

	sum := new(bls12381.G1)
	sum.SetIdentity()
	for i, s := range sets {
		// hash function calculate the hash of i, c, s, message
		// ti = H(i, c, s, message)
		tiHash := sha256.New()
		binary.Write(tiHash, binary.LittleEndian, int64(s))
		tiHash.Write(c.Bytes())
		for _, s := range sets {
			binary.Write(tiHash, binary.LittleEndian, int64(s))
		}
		for _, m := range message {
			buf, _ := m.MarshalBinary()
			tiHash.Write(buf)
		}
		tiBytes := tiHash.Sum(nil)
		ti := new(bls12381.Scalar)
		ti.SetBytes(tiBytes)

		p := new(bls12381.G1)
		p.ScalarMult(ti, proofs[i])
		sum.Add(sum, p)
	}
	return sum
}

// Verify returns true if the proof is valid or false otherwise.
func (pp *Pointproof) Verify(c *bls12381.G1, sets []int, message []bls12381.Scalar, proof *bls12381.G1) bool {
	if len(sets) != len(message) {
		panic("sets and message must have the same length")
	}

	g2Sum := new(bls12381.G2)
	g2Sum.SetIdentity()

	gtAlphaNPlus1 := bls12381.Pair(&pp.P1[0], &pp.P2[pp.N-1])

	right2 := new(bls12381.Gt)
	right2.SetIdentity()

	for i, s := range sets {
		// hash function calculate the hash of i, c, s, message
		// ti = H(i, c, s, message)
		tiHash := sha256.New()
		binary.Write(tiHash, binary.LittleEndian, int64(s))
		tiHash.Write(c.Bytes())
		for _, s := range sets {
			binary.Write(tiHash, binary.LittleEndian, int64(s))
		}
		for _, m := range message {
			buf, _ := m.MarshalBinary()
			tiHash.Write(buf)
		}
		tiBytes := tiHash.Sum(nil)
		ti := new(bls12381.Scalar)
		ti.SetBytes(tiBytes)

		t := new(bls12381.G2)
		// must substract 2 because the index of P2 is 0-based
		t.ScalarMult(ti, &pp.P2[pp.N-1-s])

		g2Sum.Add(g2Sum, t)

		prod := new(bls12381.Scalar)
		prod.Mul(&message[i], ti)

		k := new(bls12381.Gt)
		k.Exp(gtAlphaNPlus1, prod)

		right2.Mul(right2, k)
	}
	left := bls12381.Pair(c, g2Sum)

	right1 := bls12381.Pair(proof, bls12381.G2Generator())

	right := new(bls12381.Gt)
	right.Mul(right1, right2)
	return left.IsEqual(right)
}
