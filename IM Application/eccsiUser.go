package main

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// EccsiUser contains the parameters for the ECCSI user.
type EccsiUser struct {
	SSK            *big.Int // The Secret Signing Key.
	PVT            []byte   // The Public Validation Token.
	PVTx           *big.Int // The x coord of the PVT, on the elliptical curve E.
	PVTy           *big.Int // The y coord of the PVT, on the elliptical curve E.
	HS             *big.Int // The hash( G || KPAK || ID || PVT ).
	EccsiCommunity          // The public parameters for the ECCSI Community.
}

// EccsiCommunity contains the public parameters for the ECCSI Community.
type EccsiCommunity struct {
	E     elliptic.Curve // The elliptical curve NIST P-256.
	N     int            // The number of octets used to represent fields r and s in a Signature.  Also the number of octets output by the hash function.
	q     *big.Int       // The order of G in E.
	G     []byte         // The point G on the elliptical curve E.
	Gx    *big.Int       // The x coord of the point G, on the elliptical curve E.
	Gy    *big.Int       // The y coord of the point G, on the elliptical curve E.
	KPAK  []byte         // The KMS Public Authentication Key (KPAK).
	KPAKx *big.Int       // The x coord of the KPAK, on the elliptical curve E.
	KPAKy *big.Int       // The y coord of the KPAK, on the elliptical curve E.
}

// validateReceivedSSK validates the SSK against the given Identifier before being installed as a signing key.
func (user *EccsiUser) validateReceivedSSK(userID *big.Int, SSK *big.Int, PVT []byte) (err error) {

	// 1) Validate that the PVT lies on the elliptic curve E.
	// Unmarshal point on the curve in uncompressed form.
	PVTx, PVTy := elliptic.Unmarshal(user.E, PVT)
	// Check point is on the elliptical curve E.
	if !user.E.IsOnCurve(PVTx, PVTy) {
		err = fmt.Errorf("invalid PVT, does not lie on elliptical curve")
		return
	}

	// 2) Compute HS = hash( G || KPAK || ID || PVT )
	// Concatenate G || KPAK || ID || PVT.
	HSToHash := append(user.G, user.KPAK...)
	HSToHash = append(HSToHash, userID.Bytes()...)
	HSToHash = append(HSToHash, PVT...)
	// Hash ( G || KPAK || ID || PVT ) using SHA-256.
	HS, err := hashSHA256ToBigInt(HSToHash)
	if err != nil {
		return
	}

	// 3) Validate that KPAK = [SSK]G - [HS]PVT.
	// Compute [SSK]G.
	testx, testy := user.E.ScalarMult(user.Gx, user.Gy, SSK.Bytes())
	// Compute [HS]PVT.
	tmpx, tmpy := user.E.ScalarMult(PVTx, PVTy, HS.Bytes())
	// Compute KPAK + [HS]PVT (must do it this way, as no sub function in elliptical package).
	tmpx, tmpy = user.E.Add(user.KPAKx, user.KPAKy, tmpx, tmpy)
	// Marshal KPAK + [HS]PVT in uncompressed form.
	tmp := elliptic.Marshal(user.E, tmpx, tmpy)
	// Marshal [SSK]G in uncompressed form.
	test := elliptic.Marshal(user.E, testx, testy)
	// Validate KPAK + [HS]PVT = [SSK]G.
	if !bytes.Equal(tmp, test) {
		err = fmt.Errorf("invalid SSK")
		return
	}
	// SSK is valid, install as signing key.
	user.SSK = SSK
	user.PVT = PVT
	user.PVTx = PVTx
	user.PVTy = PVTy
	user.HS = HS

	return
}

// verifySignature verifies a signature against the signer's Identifier, the message and KPAK.
// If invalid, returns error, else returns nil.
func (user *EccsiUser) verifySignature(signature []byte, signerID *big.Int, message string) (err error) {

	// 1) The Verifier MUST check that the PVT lies on the elliptic curve E.
	// Find length of parameters.
	rLen := ((user.E.Params().BitSize + 7) / 8)
	PVTLen := (2 * ((user.E.Params().BitSize + 7) / 8)) + 1
	// Parse the signature.
	r := new(big.Int).SetBytes(signature[:rLen])
	PVT := signature[(len(signature) - PVTLen):]
	s := new(big.Int).SetBytes(signature[rLen:(len(signature) - PVTLen)])
	// Unmarshal point on the curve in uncompressed form.
	PVTx, PVTy := elliptic.Unmarshal(user.E, PVT)
	// Check point is on the elliptical curve E.
	if !user.E.IsOnCurve(PVTx, PVTy) {
		err = fmt.Errorf("invalid PVT")
		return
	}

	// 2) Compute HS = hash( G || KPAK || ID || PVT ).
	// Concatenate G || KPAK || ID || PVT.
	HSToHash := append(user.G, user.KPAK...)
	HSToHash = append(HSToHash, signerID.Bytes()...)
	HSToHash = append(HSToHash, PVT...)
	// Hash ( G || KPAK || ID || PVT ) using SHA-256.
	HS, err := hashSHA256ToBigInt(HSToHash)
	if err != nil {
		return
	}

	// 3) Compute HE = hash( HS || r || M ).
	// Concatenate HS || r || M.
	HEToHash := append(HS.Bytes(), r.Bytes()...)
	HEToHash = append(HEToHash, []byte(message)...)
	// Hash ( HS || r || M ) using SHA-256.
	HE, err := hashSHA256ToBigInt(HEToHash)
	if err != nil {
		return
	}

	// 4) Y = [HS]PVT + KPAK.
	// Compute scalar multiplication [HS]PVT.
	Yx, Yy := user.E.ScalarMult(PVTx, PVTy, HS.Bytes())
	// Compute point addition [HS]PVT + KPAK.
	Yx, Yy = user.E.Add(Yx, Yy, user.KPAKx, user.KPAKy)

	// 5) Compute J = [s]( [HE]G + [r]Y ).
	// Compute scalar multiplication [r]Y.
	Yx, Yy = user.E.ScalarMult(Yx, Yy, r.Bytes())
	// Compute scalar multiplication [HE]G.
	Jx, Jy := user.E.ScalarMult(user.Gx, user.Gy, HE.Bytes())
	// Compute point addition [HE]G + [r]Y.
	Jx, Jy = user.E.Add(Jx, Jy, Yx, Yy)
	// Compute scalar multiplication [s]( [HE]G + [r]Y ).
	Jx, _ = user.E.ScalarMult(Jx, Jy, s.Bytes())

	// 6) The Verifier MUST check that Jx = r modulo p, and that Jx modulo p is non-zero, before accepting the Signature as valid.
	// Verify Jx = r modulo p, if not, return error.
	if Jx.Cmp(r.Mod(r, user.q)) != 0 {
		err = fmt.Errorf("invalid signature")
		return
	}
	// Verify Jx modulo p is non-zero.
	if Jx.Mod(Jx, user.q).Cmp(big.NewInt(0)) == 0 {
		err = fmt.Errorf("invalid signature")
		return
	}

	return
}

// signMessage signs the given message using KPAK and the signer's Identifier, SSK and PVT.
// Returns the signature.
func (user *EccsiUser) signMessage(message []byte) (signature []byte, err error) {

	// 1) Choose j, a random (ephemeral) non-zero element of F_q.
	j := new(big.Int)
	for j.Cmp(big.NewInt(0)) == 0 {
		// Generate random value using cryptographically secure random generator.
		j, err = rand.Int(rand.Reader, user.q)
		if err != nil {
			err = fmt.Errorf("failed to select KSAK: %s", err.Error())
			return
		}
	}

	// 2) Compute J = [j]G.
	// Compute scalar multiplication J = [j]G.
	Jx, _ := user.E.ScalarMult(user.Gx, user.Gy, j.Bytes())
	// Assign to r the N-octet integer representing Jx.
	r := Jx

	// 3) Recall HS, and use it to compute a hash value HE = hash( HS || r || M ).
	// Concatenate HS || r || M.
	HEToHash := append(user.HS.Bytes(), r.Bytes()...)
	HEToHash = append(HEToHash, message...)
	// Hash ( HS || r || M ) using SHA-256.
	HE, err := hashSHA256ToBigInt(HEToHash)
	if err != nil {
		return
	}

	// 4) Verify that HE + r * SSK is non-zero modulo q; if this check fails, the Signer MUST abort.
	// Compute r * SSK.
	s := new(big.Int).Mul(r, user.SSK)
	// Compute HE + r * SSK.
	s.Add(s, HE)
	// Compute (HE + r * SSK) mod q.
	s.Mod(s, user.q)
	// Check if value is zero, if so, abort.
	if s.Cmp(big.NewInt(0)) == 0 {
		err = fmt.Errorf("invalid signature")
		return
	}

	// 5) Compute s' = ( (( HE + r * SSK )^-1) * j ) modulo q.
	// Compute ( HE + r * SSK )^-1.
	s.ModInverse(s, user.q)
	// Compute (( HE + r * SSK )^-1) * j.
	s.Mul(s, j)
	// Compute ( (( HE + r * SSK )^-1) * j ) modulo q.
	s.Mod(s, user.q)

	// 6) If s' is too big to fit within an N-octet integer, then set the N-octet integer s = q - s'.
	if len(s.Bytes()) > user.N {
		s.Sub(user.q, s)
	}
	// 7) Output the signature as Signature = ( r || s || PVT ).
	// Concatenate r || s || PVT.
	signature = append(r.Bytes(), s.Bytes()...)
	signature = append(signature, user.PVT...)
	// Return signature.
	return
}

// hashSHA256ToBigInt hashes the given string using SHA256 hash function.
// Returns the hash value.
func hashSHA256ToBigInt(valuetoHash []byte) (hashValue *big.Int, err error) {

	// Create new SHA256 hasher.
	hashfn := sha256.New()

	// Hash given string.
	_, err = hashfn.Write([]byte(valuetoHash))
	if err != nil {
		err = fmt.Errorf("failed to hash given string: %s : %s", valuetoHash, err.Error())
		return
	}
	// Convert hash to bigInt.
	hashValue = new(big.Int).SetBytes(hashfn.Sum(nil))
	return
}
