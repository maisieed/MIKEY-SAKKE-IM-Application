package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

// EccsiKMS contains the parameters for the ECCSI KMS.
type EccsiKMS struct {
	KSAK           *big.Int // The KMS Secret Authentication Key (KSAK).
	EccsiCommunity          // The public parameters for the ECCSI Community.
}

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

// initializeTestCommunity defines the constant values for the ECCSI community.
// These values are for test purposes only, and are not secure for application.
func (community *EccsiCommunity) initializeTestCommunity() (err error) {

	// Initialize elliptical curve NIST P-256.
	community.E = elliptic.P256()
	// Initialize N.
	community.N = 32
	// Initialize q, an odd prime that divides p+1.
	community.q = community.E.Params().N
	// Initialize random point, P, on elliptical curve.
	community.Gx = community.E.Params().Gx
	community.Gy = community.E.Params().Gy
	// Marshal point on the curve in uncompressed form.
	community.G = elliptic.Marshal(community.E, community.Gx, community.Gy)

	// Return new instance of 'kms'.
	return
}

// setupKMS randomly chooses the KMS Secret Authentication Key (KSAK) and then calculates
// the corresponding KMS Public Authentication Key (KPAK).
func (kms *EccsiKMS) setupKMS() (err error) {

	// Initialize KSAK, a random secret non-zero integer modulo q.
	kms.KSAK = big.NewInt(0)
	for kms.KSAK.Cmp(big.NewInt(0)) == 0 {
		// Generate random value using cryptographically secure random generator.
		kms.KSAK, err = rand.Int(rand.Reader, kms.q)
		if err != nil {
			err = fmt.Errorf("failed to select KSAK: %s", err.Error())
			return
		}
	}
	// Generate KPAK by computing scalar multiplication [KSAK]G.
	kms.KPAKx, kms.KPAKy = kms.E.ScalarMult(kms.Gx, kms.Gy, kms.KSAK.Bytes())
	// Marshal point on the curve in uncompressed form.
	kms.KPAK = elliptic.Marshal(kms.E, kms.KPAKx, kms.KPAKy)

	// Print values.
	fmt.Printf("KMS Secret Authentication Key (KSAK): \t%s\n", kms.KSAK.Text(16))
	fmt.Printf("KMS Public Authentication Key (KPAK x): %s\n", kms.KPAKx.Text(16))
	fmt.Printf("KMS Public Authentication Key (KPAK y): %s\n", kms.KPAKy.Text(16))

	return
}

// ConstructSskPvtPair constructs a (SSK,PVT) pair for the given Identifier.
// Returns the Secret Signing Key (SSK) and Public Validation Token (PVT).
func (kms *EccsiKMS) ConstructSskPvtPair(userID *big.Int) (SSK *big.Int, PVT []byte, PVTx *big.Int, PVTy *big.Int, HS *big.Int, err error) {

	// 1) Choose v, a random (ephemeral) non-zero element of F_q.
	v := new(big.Int)
	for v.Cmp(big.NewInt(0)) == 0 {
		// Generate random value using cryptographically secure random generator.
		v, err = rand.Int(rand.Reader, kms.q)
		if err != nil {
			err = fmt.Errorf("failed to select KSAK: %s", err.Error())
			return
		}
	}

	// 2) Compute PVT = [v]G.
	// Compute scalar multiplication [v]G.
	PVTx, PVTy = kms.E.ScalarMult(kms.Gx, kms.Gy, v.Bytes())
	// Marshal point on the curve in uncompressed form.
	PVT = elliptic.Marshal(kms.E, PVTx, PVTy)

	// 3) Compute a hash value HS = hash( G || KPAK || ID || PVT ), an N-octet integer.
	// Concatenate G || KPAK || ID || PVT.
	HSToHash := append(kms.G, kms.KPAK...)
	HSToHash = append(HSToHash, userID.Bytes()...)
	HSToHash = append(HSToHash, PVT...)
	// Hash ( G || KPAK || ID || PVT ) using SHA-256.
	HS, err = hashSHA256ToBigInt(HSToHash)
	if err != nil {
		return
	}

	// 4) Compute SSK = ( KSAK + HS * v ) modulo q
	// Compute HS * v.
	SSK = new(big.Int).Mul(HS, v)
	// Compute KSAK + HS * v.
	SSK.Add(SSK, kms.KSAK)
	// Compute ( KSAK + HS * v ) modulo q.
	SSK.Mod(SSK, kms.q)

	// 5) If either the SSK or HS is zero modulo q, the KMS MUST erase the SSK and abort.
	// Check if SSK is zero mod q, if so, abort.
	if SSK.Cmp(big.NewInt(0)) == 0 {
		err = fmt.Errorf("failed to create (SSK,PVT) pair, invalid v")
		return
	}
	// Check if HS is zero mod q, if so, abort.
	if HS.Mod(HS, kms.q).Cmp(big.NewInt(0)) == 0 {
		err = fmt.Errorf("failed to create (SSK,PVT) pair, invalid v")
		return
	}

	// Print values.
	fmt.Printf("User ID (ID): %s\n", userID.Text(16))
	fmt.Printf("Secret Signing Key (SSK): %s\n", SSK.Text(16))
	fmt.Printf("Public Validation Token (PVT): %s\n", hex.EncodeToString(PVT))

	// 6) Output the (SSK,PVT) pair.
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
