# A Secure Instant Messaging Application for the Workplace using MIKEY-SAKKE

The instant messaging (IM) application in this project uses the Sakai-Kasahara Key Encryption in Multimedia Internet KEYing (MIKEY-SAKKE) key exchange and AES-256 encryption algorithm to send messages securely between users. The IM application provides confidentiality and auditing functionality but will not allow for constant monitoring by an organisation. 

**MIKEY-SAKKE** is the key exchange protocol used by the IM application. It uses Identity-Based Public Key Cryptography to establish a shared secret value (SSV) between two users. The SSV is used to derive a symmetric session key that can be used to encrypt and decrypt messages between the two users. 

**AES-256** is the symmetric encryption algorithm used by the IM application to encrypt instant messages. It will provide end-to-end encryption between two users. 

**This project has two applications:**
- A key management application to derive key material.
- An IM application that uses end-to-end encryption to send messages securely. 

## Packages required:
- github.com/nik-u/pbc
- github.com/coreos/mantle/network/ntp
- fyne.io/fyne/v2
- github.com/lukechampine/fastxor
- github.com/Xeway/bigmath

## Dependencies:
This project uses the Pairing-Based Cryptography (PBC) library to perform the mathematical operations underlying pairing-based cryptography to implement the MIKEY-SAKKE cryptosystem. To use this library in Go, the PBC Go Wrapper is used. The dependencies for this library and installation guide, can be found at: https://pkg.go.dev/github.com/Nik-U/pbc

## How to use:
### Key Management Application
The key management application has a command-line interface with two commands.

- `setupKMS <kms_filepath>`

The setupKMS command takes one input; a file path to store the KMS key file. 
The function will establish new community values for the SAKKE and ECCSI cryptosystems. The function will then randomly select the KMS keys for SAKKE and ECCSI. All initialised values will be written to a JSON file and must be kept secret by the KMS. The application can later read these values to set up the same KMS. 

- `KMS setupUser <user_uri> <kms_filepath> <user_filepath>`

The setupUser command takes three inputs; the email address of the user, the file path of the KMS key file, and a file path to store the user key file.
The function will derive the ECCSI and SAKKE keys for the specified user using the community values and KMS keys from the KMS JSON file. The derived user keys and the community values will be written to a JSON file using the specified user file path. The system owner must then determine how to distribute this file to the user. The user will use this key file to log into their IM application.
<br>
### IM Application
The IM application has a graphical user interface (GUI) using the Fyne library.

**Logging In**
Users can log into the IM application using their email address and corresponding key file. The key file can be derived using the Key Management Application. To be valid, the key file must be for the correct email address and current month.

**Establishing New Sessions**
To chat with another user, users must first establish a session with that user. This can be done using only the receiver's email address. The IM application will perform a MIKEY-SAKKE key exchange and set up a symmetric key for the session.

**Sending Encrypted Messages**
Users can send encrypted messages to users with whom a session is established with. This will use the established session key and AES-256 encryption. Messages will be sent using end-to-end encryption and stored locally on user's devices.

**Users**
The allowed users and their associated TCP listening ports are hard-coded into the IM application for demonstration purposes. However, additional users can be added by modifying the code. These allowed users are:
- alice@workemail.com
- bob@workemail.com

Example key files for these users are provided as part of this project. 


