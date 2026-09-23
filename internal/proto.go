package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func generateKeys() ([32]byte, [32]byte, error) {
	var privateKey [32]byte
	var publicKey [32]byte

	_, err := io.ReadFull(rand.Reader, privateKey[:])
	if err != nil {
		return privateKey, publicKey, err
	}

	public, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return privateKey, publicKey, err
	}

	// convert slice to array code from https://www.slingacademy.com/rticleconverting-slices-to-arrays-in-go/
	copy(publicKey[:], public)
	return privateKey, publicKey, nil
}

func computeSharedSecret(privateKey [32]byte, peerPublicKey []byte) ([]byte, error) {

	sharedSecret, err := curve25519.X25519(privateKey[:], peerPublicKey)
	if err != nil {
		return nil, err
	}

	return sharedSecret, nil
}

func Encrypt(key, plaintext []byte) ([]byte, error) {
	gcm, err := genBlockCipher(key) // the engine
	if err != nil {
		return nil, err
	}

	// Generate random nonce for every msg
	nonce := make([]byte, gcm.NonceSize()) // gcm.NonceSize is 12 bytes
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// gcm.Seal(dst, nonce, plaintext, additionalData)
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func Decrypt(key, ciphertext []byte) ([]byte, error) {
	gcm, err := genBlockCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// split the nonce
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// builds the cryptographic machinery
func genBlockCipher(key []byte) (cipher.AEAD, error) {
	// Create the block cipher (AES core)
	block, err := aes.NewCipher(key) // automatically detects version based on key length
	if err != nil {
		return nil, err
	}

	// Wrap it in a mode of operation (GCM)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm, nil
}

// PerformHandshake handles the key exchange for both client and server.
// isServer determines the network order
func PerformHandshakeClassic(conn net.Conn, isServer bool) ([]byte, error) {
	// Generate local keys
	privKey, pubKey, err := generateKeys()
	if err != nil {
		return nil, err
	}

	remotePubKey := make([]byte, 32)

	// Network Exchange (Order depends on isServer)
	if isServer {
		if _, err := conn.Write(pubKey[:]); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(conn, remotePubKey); err != nil {
			return nil, err
		}
	} else {
		if _, err := io.ReadFull(conn, remotePubKey); err != nil {
			return nil, err
		}
		if _, err := conn.Write(pubKey[:]); err != nil {
			return nil, err
		}
	}

	// Crypto Math
	sharedSecret, err := computeSharedSecret(privKey, remotePubKey)
	if err != nil {
		return nil, err
	}

	return sharedSecret, nil
}

// implements the quantum-resistant key encapsulation methods ML-KEM (formerly Kyber)
func PerformHandshakePQ(conn net.Conn, isServer bool) ([]byte, error) {

	if isServer {
		// Server (recipient) generate new key pair (dk = private key, ek = public key)
		dk, err := mlkem.GenerateKey768() // generates a random private decapsulation key
		if err != nil {
			return nil, err
		}
		encapsulationKey := dk.EncapsulationKey().Bytes() // return public encapsulation key

		// Send encapsulation Key (public) to client
		if _, err := conn.Write(encapsulationKey); err != nil {
			return nil, err
		}

		// Read Ciphertext
		ciphertext := make([]byte, mlkem.CiphertextSize768)
		if _, err := io.ReadFull(conn, ciphertext); err != nil {
			return nil, err
		}

		// Server uses decapsulation key (private) to "unlock" ciphertext and get shared secret
		return dk.Decapsulate(ciphertext)
	} else {
		// Read encapsulation Key (public)
		encapsulationKey := make([]byte, mlkem.EncapsulationKeySize768)
		if _, err := io.ReadFull(conn, encapsulationKey); err != nil {
			return nil, err
		}

		// Initialize Key and Encapsulate
		ek, err := mlkem.NewEncapsulationKey768(encapsulationKey)
		if err != nil {
			return nil, err
		}

		// client uses ek to generate a shared secret
		sharedSecret, ciphertext := ek.Encapsulate() //ciphertext = encrypted version of the shared secret

		// Send Ciphertext back to server
		if _, err := conn.Write(ciphertext); err != nil {
			return nil, err
		}

		return sharedSecret, nil
	}
}

func DeriveHybridSessionKey(secretClassic, secretPQ []byte) ([32]byte, error) {
	combinedSecret := append(secretClassic, secretPQ...) // ... unpack slice

	// Underlying hash function for HMAC.
	hash := sha256.New

	// Non-secret context info, optional (can be nil).
	info := []byte("MLKEM-X25519-Hybrid-v1")

	// Create HKDF reader
	h := hkdf.New(hash, combinedSecret, nil, info)

	var sessionKey [32]byte
	if _, err := io.ReadFull(h, sessionKey[:]); err != nil {
		return sessionKey, err
	}
	return sessionKey, nil
}
