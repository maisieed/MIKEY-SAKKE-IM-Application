package main

import (
	"fmt"
	"log"
	"math/big"
	"os"
)

// CommunityUsers maps URI to address of users of the community.
var CommunityUsers = map[string]string{
	"alice@workemail.com": "localhost:8080",
	"bob@workemail.com":   "localhost:8081",
}

// KMS contains the parameters for the KMS.
type KMS struct {
	Eccsi EccsiKMS // The parameters for ECCSI.
	Sakke SakkeKMS // The parameters for SAKKE.
}

// User contains the parameters for the user.
type User struct {
	URI   string    // The Uniform Resource Identifier (URI) of the user.
	ID    *big.Int  // The user ID.
	Eccsi EccsiUser // The parameters for ECCSI.
	Sakke SakkeUser // The parameters for SAKKE.
}

func main() {

	// Determine which function to run.
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "setupKMS":
			// If user has selected setupKMS, initialize new KMS.
			// Check for expected number of arguments.
			if len(os.Args) != 3 {
				break
			}
			// Initialize arguments.
			kmsFilepath := os.Args[2]
			// Initialize KMS.
			var kms KMS
			err := kms.initializeKMS("")
			if err != nil {
				log.Fatalln(err)
			}
			// Write KMS to specified filepath.
			err = kms.writeKMS(kmsFilepath)
			if err != nil {
				log.Fatalln(err)
			}
			// Exit successfully.
			os.Exit(0)

		case "setupUser":
			// If user has selected setupUser, initialize user.
			// Check for expected number of arguments.
			if len(os.Args) != 5 {
				break
			}
			// Initialize arguments.
			userURI := os.Args[2]
			kmsFilepath := os.Args[3]
			userFilepath := os.Args[4]
			// Initialize KMS.
			var kms KMS
			err := kms.initializeKMS(kmsFilepath)
			if err != nil {
				log.Fatalln(err)
			}
			// Initialize specified user.
			err = kms.initializeUser(userURI, userFilepath)
			if err != nil {
				log.Fatalln(err)
			}
			// Exit successfully.
			os.Exit(0)
		}
	}
	fmt.Println("Expected input: KMS setupKMS <kms_filepath>")
	fmt.Println("                KMS setupUser <user_uri> <kms_filepath> <user_filepath>")
}

// initializeUser initializes the community values for a user and then computes
// the user's Secret Signing Key (SSK), Public Validation Token (PVT) and Receiver Secret Key (RSK).
// Writes the user data to the given filepath.
func (kms *KMS) initializeUser(URI string, filepath string) (err error) {

	// Check user is a member of the community.
	if _, ok := CommunityUsers[URI]; !ok {
		err = fmt.Errorf("user is not a member of the community")
		return
	}
	// Create new instance of 'User'.
	user := User{URI: URI}

	// Compute user ID using URI.
	user.ID, err = generateIDInteger(user.URI)
	if err != nil {
		return
	}
	// Set community values as those of the KMS.
	user.Eccsi.EccsiCommunity = kms.Eccsi.EccsiCommunity
	user.Sakke.SakkeCommunity = kms.Sakke.SakkeCommunity

	// Construct (SSK,PVT) pair for user.
	user.Eccsi.SSK, user.Eccsi.PVT, user.Eccsi.PVTx, user.Eccsi.PVTy, user.Eccsi.HS, err = kms.Eccsi.ConstructSskPvtPair(user.ID)
	if err != nil {
		return
	}
	// Construct RSK for user.
	user.Sakke.RSK = kms.Sakke.secretKeyExtraction(user.ID)

	// Write user to specified filepath.
	err = user.writeUser(filepath)

	return
}

// initializeKMS initializes the community values for the KMS and then computes
// the KMS Secret Authentication Key (KSAK), KMS Public Authentication Key (KPAK),
// KMS Master Secret (zT) and KMS Public key (ZT).
func (kms *KMS) initializeKMS(filepath string) (err error) {

	if filepath == "" {
		// If no filepath, use test data to initialize community values for KMS.
		// Initialize ECCSI community.
		err = kms.Eccsi.EccsiCommunity.initializeTestCommunity()
		if err != nil {
			return
		}
		// Initialize Sakke community.
		kms.Sakke.initializeTestCommunity()
	} else {
		// If filepath, read in community values for KMS.
		err = kms.readKMS(filepath)
		if err != nil {
			return
		}
	}
	// If not provided in community values, construct KPAK and KSAK for KMS.
	if kms.Eccsi.KPAK == nil || kms.Eccsi.KSAK == nil {
		err = kms.Eccsi.setupKMS()
		if err != nil {
			return
		}
	}
	// If not provided in community values, construct ZT and zT for kms.
	if kms.Sakke.ZT == nil || kms.Sakke.zT == nil {
		err = kms.Sakke.setup()
		if err != nil {
			return
		}
	}
	return
}
