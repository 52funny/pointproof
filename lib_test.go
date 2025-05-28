package pointproof

import (
	"crypto/rand"
	"flag"
	"testing"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/stretchr/testify/assert"
)

var n = flag.Int("n", 1024, "number of points")

func BenchmarkCommitment(b *testing.B) {
	p := Setup(*n)
	m := make([]bls12381.Scalar, *n)
	for i := range m {
		m[i].Random(rand.Reader)
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		p.Commitment(m)
	}
}

func BenchmarkProof(b *testing.B) {
	p := Setup(*n)
	m := make([]bls12381.Scalar, *n)
	for i := range len(m) {
		m[i].Random(rand.Reader)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		p.Proof(m, i%*n)
	}
}

func TestVerify(t *testing.T) {
	p := Setup(*n)
	m := make([]bls12381.Scalar, *n)

	for i := range m {
		m[i].Random(rand.Reader)
	}

	c := p.Commitment(m)
	proof := p.Proof(m, 0)

	agg := p.Aggregate(c, []int{0}, m[0:1], []*bls12381.G1{proof})

	res := p.Verify(c, []int{0}, m[0:1], agg)
	assert.True(t, res, "Verification should succeed")
}

func TestVerify2(t *testing.T) {
	p := Setup(*n)
	m := make([]bls12381.Scalar, *n)

	for i := range m {
		m[i].Random(rand.Reader)
	}

	idx := 2
	c := p.Commitment(m)
	proof := p.Proof(m, idx)

	agg := p.Aggregate(c, []int{idx}, []bls12381.Scalar{m[idx]}, []*bls12381.G1{proof})

	res := p.Verify(c, []int{idx}, []bls12381.Scalar{m[idx]}, agg)
	assert.True(t, res, "Verification should succeed")
}
