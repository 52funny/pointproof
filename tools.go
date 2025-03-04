package pointproof

import (
	"crypto/sha256"

	"github.com/cloudflare/circl/ecc/bls12381"
)

func MessageToScalar(message []string) []bls12381.Scalar {
	res := make([]bls12381.Scalar, 0, len(message))
	for _, m := range message {
		ret := sha256.Sum256([]byte(m))
		sca := bls12381.Scalar{}
		sca.SetBytes(ret[:])
		res = append(res, sca)
	}
	return res
}
