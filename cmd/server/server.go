package server

import (
	"fmt"
	"io"
	"log"
	"net"

	"github.com/Eklund2012/pq-hybrid-kex/internal"
)

const (
	isServer = true
)

func StartServer() {
	conn, err := net.Listen("tcp", ":9000") // Servers listens on arbitrary port
	if err != nil {
		log.Fatalln(err)
	}
	defer conn.Close()
	fmt.Println("Server listening on port 9000...")

	for {
		client, err := conn.Accept() // Client connects
		if err != nil {
			log.Println("Failed to connect client: ", err)
			continue
		}
		go handleConn(client)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	// Performs DH / X25519 KE
	secretClassic, err := internal.PerformHandshakeClassic(conn, isServer)
	if err != nil {
		log.Printf("X25519 handshake failed: %v", err)
		return
	}

	secretPQ, err := internal.PerformHandshakePQ(conn, isServer)
	if err != nil {
		log.Printf("ML-KEM handshake failed: %v", err)
		return
	}

	sessionKey, err := internal.DeriveHybridSessionKey(secretClassic, secretPQ)
	if err != nil {
		log.Printf("Session key failed: %v", err)
		return
	}

	buffer := make([]byte, 1024) // Buffer for incoming messages from client
	for {
		// Read message from client
		n, err := conn.Read(buffer)
		if err != nil {
			if err == io.EOF {
				log.Println("Client disconnected.")
			} else {
				log.Printf("Read error: %v", err)
			}
			return
		}

		// Decrypt request
		ciphertext := buffer[:n]
		plaintext, err := internal.Decrypt(sessionKey[:], ciphertext)
		if err != nil {
			fmt.Println("Decryption failed:", err)
			continue
		}

		fmt.Printf("Server Received: %s\n", plaintext)

		// Create response
		responseMsg := fmt.Sprintf("I have received %s", string(plaintext))

		// Encrypt resonse
		encryptedResponse, err := internal.Encrypt(sessionKey[:], []byte(responseMsg))
		if err != nil {
			log.Printf("Encryption failed: %v", err)
			continue
		}

		_, err = conn.Write(encryptedResponse)
		if err != nil {
			log.Printf("Write error: %v", err)
			return
		}
	}
}
