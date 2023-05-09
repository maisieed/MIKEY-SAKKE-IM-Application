package main

import (
	"fmt"
	"math/big"

	"github.com/Nik-U/pbc"
)

// SakkeKMS contains the parameters for the SAKKE KMS.
type SakkeKMS struct {
	zT *pbc.Element // KMS master key (zT).
	SakkeCommunity
}

// SakkeUser contains the parameters for the SAKKE User.
type SakkeUser struct {
	RSK *pbc.Element // Receiver secret key.
	SakkeCommunity
}

// SakkeCommunity contains the public parameters for the community.
type SakkeCommunity struct {
	n       *big.Int     // A security parameter; size of symmetric keys.
	ZT      *pbc.Element // KMS public key (ZT).
	pbits   *big.Int     // The bit size of p, a prime that is order of finite field F_p.
	qbits   *big.Int     // The bit size of q, a prime that is order of group elements.
	params  *pbc.Params  // The parameters to create the elliptical curve pairing.
	pairing *pbc.Pairing // Pairing on elliptical curve over field F_p.
	P       *pbc.Element // Point on elliptical curve in G1 of order q.
	g       *pbc.Element // Pairing g = <P, P>.
}

// initializeTestCommunity defines the constant values for the SAKKE community.
// These values are for test purposes only, and are not secure for application.
func (community *SakkeCommunity) initializeTestCommunity() {

	// Initialize the number of bits of p.
	community.pbits = big.NewInt(512)
	// Initialize the number of bits of q.
	community.qbits = big.NewInt(160)
	// Initialize n, security parameter.
	community.n = big.NewInt(256)
	// Initialize new pairing on curve using 'pbits' and 'qbits'.
	community.params = pbc.GenerateA(uint32(community.qbits.Int64()), uint32(community.pbits.Int64()))
	community.pairing = community.params.NewPairing()
	// Initialize point P on curve.
	community.P = community.pairing.NewG1().Rand()
	// Initialize g = <P,P>.
	community.g = community.pairing.NewGT().Pair(community.P, community.P)
}

// setup randomly chooses its KMS Master Secret (zT) and then calculates
// the corresponding KMS Public Key (ZT).
func (kms *SakkeKMS) setup() (err error) {

	// 1) Generate KMS Master Secret (zT), an random integer in range 2 - (q-1).
	// Generate random value using cryptographically secure random generator.
	kms.zT = kms.pairing.NewZr().Rand()

	// 2) Generate KMS public key (ZT) by computing scalar multiplication [zT]P.
	kms.ZT = kms.pairing.NewG1().MulZn(kms.P, kms.zT)

	// Print values.
	fmt.Printf("KMS Master Secret (zT): \t%d\n", kms.zT)
	fmt.Printf("KMS Public key (ZT): \t%s\n", kms.ZT.String())

	return
}

// secretKeyExtraction derives the RSK for the given Identifier.
// Returns the RSK.
func (kms *SakkeKMS) secretKeyExtraction(userID *big.Int) (rsk *pbc.Element) {

	// 1) Compute K_(a, T) = [(a + zT)^-1]P.
	// Compute a + zT.
	tmp := kms.pairing.NewZr().SetBig(userID)
	tmp.Add(tmp, kms.zT)
	// Compute modular inverse (a + zT)^-1.
	tmp.Invert(tmp)
	// Compute scalar multiplication [(a + zT)^-1]P in E(F_p).
	rsk = kms.pairing.NewG1().MulZn(kms.P, tmp)
	// Print values.
	fmt.Printf("Receiver Secret Key (RSK):\t%s\n", rsk.String())

	// Return RSK.
	return
}
