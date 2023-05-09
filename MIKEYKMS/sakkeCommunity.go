package main

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"

	"github.com/Nik-U/pbc"
)

// writeKMS writes the 'KMS' values to the specified JSON file.
func (kms *KMS) writeKMS(filepath string) (err error) {

	// Initialize new map.
	encodedValues := map[string]interface{}{}

	// Add SAKKE values to 'encodedValues'.
	encodedValues["Sakke"] = kms.Sakke.writeSakkeKMSValues()
	if err != nil {
		return
	}
	// Add ECCSI values to 'encodedValues'.
	encodedValues["Eccsi"] = kms.Eccsi.writeEccsiKMSValues()

	// Format 'encodedValues' for JSON file.
	file, err := json.MarshalIndent(encodedValues, "", "	")
	if err != nil {
		err = fmt.Errorf("failed to marshal 'KMS' values: %s", err.Error())
		return
	}
	// Write 'encodedValues' to specified JSON file.
	err = ioutil.WriteFile(filepath, file, 0644)
	if err != nil {
		err = fmt.Errorf("failed to write to JSON file: %s: %s", filepath, err.Error())
	}
	return
}

// readKMS reads the 'KMS' values from the specified JSON file.
func (kms *KMS) readKMS(filepath string) (err error) {

	// Initialize new map.
	encodedValues := map[string]interface{}{}

	// Read in specified JSON file.
	file, err := ioutil.ReadFile(filepath)
	if err != nil {
		err = fmt.Errorf("failed to read JSON file: %s: %s", filepath, err.Error())
		return
	}
	// Unmarshal file into map.
	err = json.Unmarshal(file, &encodedValues)
	if err != nil {
		err = fmt.Errorf("failed to unmarshal 'KMS' values: %s", err.Error())
		return
	}
	// Add SAKKE values to 'KMS'.
	err = kms.Sakke.readSakkeKMSValues(encodedValues["Sakke"].(map[string]interface{}))
	if err != nil {
		return
	}
	// Add ECCSI values to 'KMS'.
	err = kms.Eccsi.readEccsiKMSValues(encodedValues["Eccsi"].(map[string]interface{}))
	if err != nil {
		return
	}
	// Return updated 'KMS'.
	return
}

// writeUser writes the 'User' values to the specified JSON file.
func (user *User) writeUser(filepath string) (err error) {

	// Initialize new map.
	encodedValues := map[string]interface{}{}

	// Add SAKKE values to 'encodedValues'.
	encodedValues["Sakke"] = user.Sakke.writeSakkeUserValues()
	if err != nil {
		return
	}
	// Add ECCSI values to 'encodedValues'.
	encodedValues["Eccsi"] = user.Eccsi.writeEccsiUserValues()

	// Format 'encodedValues' for JSON file.
	file, err := json.MarshalIndent(encodedValues, "", "	")
	if err != nil {
		err = fmt.Errorf("failed to marshal 'User' values: %s", err.Error())
		return
	}
	// Write 'encodedValues' to specified JSON file.
	err = ioutil.WriteFile(filepath, file, 0644)
	if err != nil {
		err = fmt.Errorf("failed to write to JSON file: %s: %s", filepath, err.Error())
	}
	return
}

// writeSakkeKMSValues converts the SAKKE KMS values, including the community values, from the 'SakkeKMS' struct
// to a type that can be represented in a JSON file.
// Returns the encoded values in a map.
func (kms *SakkeKMS) writeSakkeKMSValues() (encodedValues map[string]interface{}) {

	// Convert SAKKE community values.
	encodedValues = kms.writeSakkeCommunityValues()
	// Convert 'zT' from PBC element into hex.
	encodedValues["zT"] = kms.zT.BigInt().Text(16)

	return
}

// writeSakkeUserValues converts the SAKKE User values, including the community values, from the 'SakkeUser' struct
// to a type that can be represented in a JSON file.
// Returns the encoded values in a map.
func (user *SakkeUser) writeSakkeUserValues() (encodedValues map[string]interface{}) {

	// Convert SAKKE community values.
	encodedValues = user.writeSakkeCommunityValues()
	// Convert 'RSK' from PBC element into base64 encoded []byte.
	encodedValues["RSK"] = base64.StdEncoding.EncodeToString(user.RSK.CompressedBytes())

	return
}

// writeSakkeCommunityValues converts the SAKKE community values from the 'SakkeCommunity' struct
// to a type that can be represented in a JSON file.
// Returns the encoded values in a map.
func (community *SakkeCommunity) writeSakkeCommunityValues() (encodedValues map[string]interface{}) {

	// Initialize new map.
	encodedValues = map[string]interface{}{}
	// Convert 'n' from big.Int into Hex.
	encodedValues["n"] = community.n.Text(16)
	// Convert 'pbits' from big.Int into Hex.
	encodedValues["pbits"] = community.pbits.Text(16)
	// Convert 'qbits' from big.Int into Hex.
	encodedValues["qbits"] = community.qbits.Text(16)
	// Convert 'params' to string.
	encodedValues["params"] = community.params.String()
	// Convert 'P' from PBC element into base64 encoded []byte.
	encodedValues["P"] = base64.StdEncoding.EncodeToString(community.P.CompressedBytes())
	// Convert 'ZT' from PBC element into base64 encoded []byte.
	encodedValues["ZT"] = base64.StdEncoding.EncodeToString(community.ZT.CompressedBytes())

	return
}

// readSakkeKMSValues converts the SAKKE KMS values, including the community values, read from a JSON file
// to the valid type for the 'SakkeKMS' struct.
// Adds the decoded values to 'SakkeKMS'.
func (kms *SakkeKMS) readSakkeKMSValues(encodedValues map[string]interface{}) (err error) {

	// Convert SAKKE community values.
	err = kms.readSakkeCommunityValues(encodedValues)
	if err != nil {
		return
	}
	// Convert 'zT' from big.Int into PBC element if set.
	if zTString, ok := encodedValues["zT"].(string); ok {
		zT, isSuccess := new(big.Int).SetString(zTString, 16)
		if !isSuccess {
			err = fmt.Errorf("failed to read 'zT' from JSON file")
			return
		}
		kms.zT = kms.pairing.NewZr().SetBig(zT)
	}

	return
}

// readSakkeCommunityValues converts the SAKKE community values read from a JSON file
// to the valid type for the 'SakkeCommunity' struct.
// Adds the decoded values to 'SakkeCommunity'.
func (community *SakkeCommunity) readSakkeCommunityValues(encodedValues map[string]interface{}) (err error) {

	var isSuccess bool // True if value converted successfully, else false.

	// Convert 'n' from Hex into big.Int.
	community.n, isSuccess = new(big.Int).SetString(encodedValues["n"].(string), 16)
	if !isSuccess {
		err = fmt.Errorf("failed to read 'n' from JSON file")
		return
	}
	// Convert 'pbits' from Hex into big.Int.
	community.pbits, isSuccess = new(big.Int).SetString(encodedValues["p"].(string), 16)
	if !isSuccess {
		err = fmt.Errorf("failed to read 'p' from JSON file")
		return
	}
	// Convert 'qbits' from Hex into big.Int.
	community.qbits, isSuccess = new(big.Int).SetString(encodedValues["q"].(string), 16)
	if !isSuccess {
		err = fmt.Errorf("failed to read 'q' from JSON file")
		return
	}
	// Convert 'params' from string into PBC params.
	community.params, err = pbc.NewParamsFromString(encodedValues["params"].(string))
	if err != nil {
		err = fmt.Errorf("failed to read 'params' from JSON file: %s", err.Error())
		return
	}
	// Compute pairing on curve using 'params'.
	community.pairing = community.params.NewPairing()

	// Convert 'P' from base64 encoded []byte into PBC element.
	p, err := base64.StdEncoding.DecodeString(encodedValues["P"].(string))
	if err != nil {
		err = fmt.Errorf("failed to read 'p' from JSON file: %s", err.Error())
		return
	}
	community.P = community.pairing.NewG1().SetCompressedBytes(p)

	// Convert 'ZT' from base64 encoded []byte into PBC element.
	ZT, err := base64.StdEncoding.DecodeString(encodedValues["ZT"].(string))
	if err != nil {
		err = fmt.Errorf("failed to read 'ZT' from JSON file: %s", err.Error())
		return
	}
	community.ZT = community.pairing.NewG1().SetCompressedBytes(ZT)

	// Compute pairing g = <P,P>.
	community.g = community.pairing.NewGT().Pair(community.P, community.P)

	return
}

// writeEccsiKMSValues converts the ECCSI KMS values, including the community values, from the 'EccsiKMS' struct
// to a type that can be represented in a JSON file.
// Returns the encoded values in a map.
func (kms *EccsiKMS) writeEccsiKMSValues() (encodedValues map[string]interface{}) {

	// Convert ECCSI community values.
	encodedValues = kms.writeEccsiCommunityValues()
	// Convert 'KSAK' from big.Int into Hex.
	encodedValues["KSAK"] = kms.KSAK.Text(16)

	return
}

// writeEccsiUserValues converts the ECCSI User values, including the community values, from the 'EccsiUser' struct
// to a type that can be represented in a JSON file.
// Returns the encoded values in a map.
func (user *EccsiUser) writeEccsiUserValues() (encodedValues map[string]interface{}) {

	// Convert ECCSI community values.
	encodedValues = user.writeEccsiCommunityValues()
	// Convert 'SSK' from big.Int into Hex.
	encodedValues["SSK"] = user.SSK.Text(16)
	// Convert 'PVTx' from big.Int into Hex.
	encodedValues["PVTx"] = user.PVTx.Text(16)
	// Convert 'PVTy' from big.Int into Hex.
	encodedValues["PVTy"] = user.PVTy.Text(16)
	// Convert 'HS' from big.Int into Hex.
	encodedValues["HS"] = user.HS.Text(16)

	return
}

// writeEccsiCommunityValues converts the ECCSI community values from the 'EccsiCommunity' struct
// to a type that can be represented in a JSON file.
// Returns the encoded values in a map.
func (community *EccsiCommunity) writeEccsiCommunityValues() (encodedValues map[string]interface{}) {

	// Initialize new map.
	encodedValues = map[string]interface{}{}
	// Add 'N'.
	encodedValues["N"] = community.N
	// Convert 'q' from big.Int to Hex.
	encodedValues["q"] = community.q.Text(16)
	// Convert 'Gx' from big.Int to Hex.
	encodedValues["Gx"] = community.Gx.Text(16)
	// Convert 'Gy' from big.Int to Hex.
	encodedValues["Gy"] = community.Gy.Text(16)
	// Convert 'KPAKx' from big.Int to Hex.
	encodedValues["KPAKx"] = community.KPAKx.Text(16)
	// Convert 'KPAKy' from big.Int to Hex.
	encodedValues["KPAKy"] = community.KPAKy.Text(16)

	return
}

// readEccsiKMSValues converts the ECCSI KMS values, including the community values, read from a JSON file
// to the valid type for the 'EccsiKMS' struct.
// Adds the decoded values to 'EccsiKMS'.
func (kms *EccsiKMS) readEccsiKMSValues(encodedValues map[string]interface{}) (err error) {

	var isSuccess bool // True if value converted successfully, else false.

	// Convert ECCSI community values.
	err = kms.readEccsiCommunityValues(encodedValues)
	if err != nil {
		return
	}
	// Convert 'KSAK' from Hex into big.Int if set.
	if KSAKString, ok := encodedValues["KSAK"].(string); ok {
		kms.KSAK, isSuccess = new(big.Int).SetString(KSAKString, 16)
		if !isSuccess {
			err = fmt.Errorf("failed to read 'KSAK' from JSON file")
		}
	}

	return
}

// readEccsiCommunityValues converts the Eccsi community values read from a JSON file
// to the valid type for the 'EccsiCommunity' struct.
// Adds the decoded values to 'EccsiCommunity'.
func (community *EccsiCommunity) readEccsiCommunityValues(encodedValues map[string]interface{}) (err error) {

	var isSuccess bool // True if value converted successfully, else false.

	// Compute elliptical curve NIST P-256.
	community.E = elliptic.P256()
	// Add 'N'.
	community.N = int(encodedValues["N"].(float64))

	// Convert 'q' from Hex to big.Int.
	community.q, isSuccess = new(big.Int).SetString(encodedValues["q"].(string), 16)
	if !isSuccess {
		err = fmt.Errorf("failed to read 'q' from JSON file")
		return
	}
	// Convert 'Gx' from Hex to big.Int.
	community.Gx, isSuccess = new(big.Int).SetString(encodedValues["Gx"].(string), 16)
	if !isSuccess {
		err = fmt.Errorf("failed to read 'Gx' from JSON file")
		return
	}
	// Convert 'Gy' from Hex to big.Int.
	community.Gy, isSuccess = new(big.Int).SetString(encodedValues["Gy"].(string), 16)
	if !isSuccess {
		err = fmt.Errorf("failed to read 'Gx' from JSON file")
		return
	}
	// Convert 'KPAKx' from Hex to big.Int.
	community.KPAKx, isSuccess = new(big.Int).SetString(encodedValues["KPAKx"].(string), 16)
	if !isSuccess {
		err = fmt.Errorf("failed to read 'KPAKx' from JSON file")
		return
	}
	// Convert 'KPAKy' from Hex to big.Int.
	community.KPAKy, isSuccess = new(big.Int).SetString(encodedValues["KPAKy"].(string), 16)
	if !isSuccess {
		err = fmt.Errorf("failed to read 'KPAKy' from JSON file")
		return
	}
	// Check 'G' is on the curve 'E'.
	if !community.E.IsOnCurve(community.Gx, community.Gy) {
		err = fmt.Errorf("point G is not on the elliptical curve NIST P256")
		return
	}
	// Check 'KPAK' is on the curve 'E'.
	if !community.E.IsOnCurve(community.KPAKx, community.KPAKy) {
		err = fmt.Errorf("point KPAK is not on the elliptical curve NIST P256")
		return
	}
	// Find 'G' on curve.
	community.G = elliptic.Marshal(community.E, community.Gx, community.Gy)

	// Find KPAK on curve.
	community.KPAK = elliptic.Marshal(community.E, community.KPAKx, community.KPAKy)

	return
}
