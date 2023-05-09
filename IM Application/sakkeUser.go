package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math"
	"math/big"

	"github.com/Nik-U/pbc"
	"github.com/Xeway/bigmath"
)

// SakkeUser contains the parameters for the SAKKE User.
type SakkeUser struct {
	RSK *pbc.Element // Receiver Secret Key (RSK).
	SakkeCommunity
}

// SakkeCommunity contains the public parameters for the community.
type SakkeCommunity struct {
	n       *big.Int     // A security parameter; size of symmetric keys.
	ZT      *pbc.Element // KMS public key (ZT).
	pbits   *big.Int     // The bit size of p, a prime that is order of finite field F_p.
	qbits   *big.Int     // The bit size of q, a prime that is order of group elements.
	params  *pbc.Params  // The parameters to create the elliptical curve pairing.
	q       *big.Int     // The prime that is order of group elements.
	pairing *pbc.Pairing // Pairing on elliptical curve over field F_p.
	P       *pbc.Element // Point on elliptical curve in G1 of order q.
	g       *pbc.Element // Pairing g = <P, P>.
}

// verifyRSK verifies the RSK against the given Identifier before being installed as a key.
// Returns an error if invalid.
func (user *SakkeUser) verifyRSK(userID *big.Int, rsk *pbc.Element) (err error) {

	// 1) Compute < [a]P + Z, K_(a,T) >.
	// Compute scalar multiplication [a]P in E(F_p).
	tmp := user.pairing.NewZr().SetBig(userID)
	test := user.pairing.NewG1().MulZn(user.P, tmp)
	// Compute point addition [a]P + Z in E(F_p).
	test.Add(test, user.ZT)
	// Compute pairing < [a]P + Z, K_(a,T) >.
	pair := user.pairing.NewGT().Pair(test, rsk)

	// 2) Check the following equation holds: < [a]P + Z, K_(a,T) > = g.
	// Check < [a]P + Z, K_(a,T) > = g, where g = <P,P>.
	if !pair.Equals(user.g) {
		err = fmt.Errorf("invalid RSK")
		return
	}
	// If valid, add RSK to 'SakkeUser'.
	user.RSK = rsk

	return
}

// encapsulateData selects the SSV and forms the encapsulated data to send to the receiver.
// Returns the SSV and encapsulated data.
func (user *SakkeUser) encapsulateData(receiverID *big.Int) (ssv *big.Int, encapsulatedData []byte, err error) {

	// 1) Select a random ephemeral integer value for the SSV in the range 0 to 2^n - 1.
	// Define maximum value, 2^n - 1.
	max := new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), user.n, nil), big.NewInt(1))
	// Select random value using cryptographically secure random generator.
	ssv, err = rand.Int(rand.Reader, max)
	if err != nil {
		err = fmt.Errorf("failed to select SSV: %s", err.Error())
		return
	}

	// 2) Compute r = HashToIntegerRange(SSV || b, q, Hash).
	// Concatenate SSV with receiver ID.
	s := ssv.String() + receiverID.String()
	// Hash concatenated string to integer range using SHA256.
	r, err := hashToIntegerRangeSHA256(s, user.q)
	if err != nil {
		return
	}

	// 3) Compute R_(b,S) = [r]([b]P + ZS) in E(F_p).
	// Compute scalar multiplication [b]P in E(F_p).
	R := user.pairing.NewG1().MulBig(user.P, receiverID)
	// Compute point addition [b]P + Z_S in E(F_p).
	R.Add(R, user.ZT)
	// Compute scalar multiplication [r]([b]P + ZS) in E(F_p).
	R.MulBig(R, r)

	// 4) Compute the Hint, H.
	// 4a) Compute g^r.
	gr := user.pairing.NewGT().PowBig(user.g, r)

	// 4b) Compute H := SSV XOR HashToIntegerRange(g^r, 2^n, Hash).
	// Hash g^r to integer range using SHA256.
	hashedGR, err := hashToIntegerRangeSHA256(gr.String(), new(big.Int).Exp(big.NewInt(2), user.n, nil))
	if err != nil {
		return
	}
	// Compute H by XORing SSV and hashed g^r.
	H := new(big.Int).Xor(ssv, hashedGR)

	// 5) Form the Encapsulated Data ( R_(b,S), H ), and transmit it to B.
	encapsulatedData = append(R.Bytes(), H.Bytes()...)

	// 6) Output SSV for use to derive key material for the application to be keyed.
	return
}

// decapsulateData derives and verifies the SSV from the sender's encapsulated data.
// Returns the SSV.
func (user *SakkeUser) decapsulateData(userID *big.Int, encapsulatedData []byte) (ssv *big.Int, err error) {

	// 1) Parse the Encapsulated Data ( R_(b,S), H ), and extract R_(b,S) and H;
	// Find length of R.
	rLen := user.pairing.G1Length()
	// Extract R and H from encapsulated data.
	encapsulatedR := encapsulatedData[:rLen]
	H := new(big.Int).SetBytes(encapsulatedData[rLen:])

	// Unmarshal R in uncompressed form.
	R := user.pairing.NewG1().SetBytes(encapsulatedR)

	// 2) Compute w := < R_(b,S), K_(b,S) >.
	w := user.pairing.NewGT().Pair(R, user.RSK)

	// 3) Compute SSV = H XOR HashToIntegerRange( w, 2^n, Hash );
	// Hash w to integer range using SHA256.
	hashedW, err := hashToIntegerRangeSHA256(w.String(), new(big.Int).Exp(big.NewInt(2), user.n, nil))
	if err != nil {
		return
	}
	// Compute SSV by XORing H and hashed w.
	ssv = new(big.Int).Xor(H, hashedW)

	// 4) Compute r = HashToIntegerRange( SSV || b, q, Hash );
	// Concatenate SSV with receiver ID.
	s := ssv.String() + userID.String()
	// Hash concatenated string to integer range using SHA256.
	r, err := hashToIntegerRangeSHA256(s, user.q)
	if err != nil {
		return
	}

	// 5) Compute TEST = [r]([b]P + Z_S) in E(F_p).
	// Compute scalar multiplication [b]P in E(F_p).
	test := user.pairing.NewG1().MulBig(user.P, userID)
	// Compute point addition [b]P + ZS in E(F_p).
	test.Add(test, user.ZT)
	// Compute scalar multiplication [r]([b]P + ZS) in E(F_p).
	test.MulBig(test, r)
	// If TEST does not equal R_(b,S), then B MUST NOT use the SSV to derive key material.
	if !test.Equals(R) {
		err = fmt.Errorf("invalid SSV")
		return
	}

	// 6) Output SSV for use to derive key material for the application to be keyed.
	return
}

// hashToIntegerRange hashes the given string to an integer range using SHA-256.
// Returns an integer in the range 0 to n-1.
func hashToIntegerRangeSHA256(s string, n *big.Int) (*big.Int, error) {

	// 1) Let A = hashfn( s ).
	A, err := hashSHA256ToBytes([]byte(s))
	if err != nil {
		return nil, err
	}

	// 2) Let h_0 = 00...00, a string of null bits of length hashlen bits.
	h_i := make([]byte, sha256.Size)
	for i := range h_i {
		// Set rune h[i] to be ASCII null.
		h_i[i] = 0x00
	}

	// 3) Let l = Ceiling(lg(n)/hashlen).
	// This cannot be done using 'math/big'. Have to use external package.
	l := int(math.Ceil(bigmath.IntLog10(n) / sha256.Size))

	// 4) For each i in 1 to l, do:
	var concatenateV []byte
	for i := 0; i < l; i++ {

		// 4a) Let h_i = hashfn(h_(i - 1)).
		h_i, err = hashSHA256ToBytes(h_i)
		if err != nil {
			return nil, err
		}
		// 4b) Let v_i = hashfn(h_i || A).
		v_i, err := hashSHA256ToBytes(append(h_i, A...))
		if err != nil {
			return nil, err
		}
		// 5) Let v' = v_1 || ...  || v_l
		concatenateV = append(concatenateV, v_i...)
	}

	// 6) Let v = v' mod n.
	// Convert 'concatenateV' to a integer.
	v := new(big.Int).SetBytes(concatenateV)

	// Return v = v mod n.
	return v.Mod(v, n), nil
}

// hashSHA256ToBytes hashes the given []byte using SHA256 hash function.
// Returns the hash value as a []byte.
func hashSHA256ToBytes(valueToHash []byte) (hashValue []byte, err error) {

	// Create new SHA256 hasher.
	hashfn := sha256.New()

	// Hash given string.
	_, err = hashfn.Write(valueToHash)
	if err != nil {
		err = fmt.Errorf("failed to hash given string: %s : %s", string(valueToHash), err.Error())
		return
	}
	// Convert hash to string.
	hashValue = hashfn.Sum(nil)
	return
}
