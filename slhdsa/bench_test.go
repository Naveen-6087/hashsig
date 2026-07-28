package slhdsa

import "testing"

func BenchmarkSLHDSA(b *testing.B) {
	msg := make([]byte, 64)
	for _, p := range []Params{"SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHAKE-128f"} {
		pub, priv, err := GenerateKey(p, nil)
		if err != nil {
			b.Fatal(err)
		}
		sig, _ := Sign(p, priv, msg, nil, true)
		b.Run("sign/"+string(p), func(b *testing.B) {
			for b.Loop() {
				if _, err := Sign(p, priv, msg, nil, false); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("verify/"+string(p), func(b *testing.B) {
			for b.Loop() {
				if err := Verify(p, pub, msg, sig, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
