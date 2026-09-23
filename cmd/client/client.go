package client

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/Eklund2012/pq-hybrid-kex/internal"
)

func StartClient() {
	conn, err := net.Dial("tcp", ":9000") // Client starts and connects to server
	if err != nil {
		log.Printf("Could not connect to server: %v", err)
		return
	}
	defer conn.Close()

	fmt.Println("Connected to server")
	handleConn(conn)
}

func handleConn(conn net.Conn) {

	// Peforms DH / X25519 KE
	secretClassic, err := internal.PerformHandshakeClassic(conn, false)
	if err != nil {
		log.Printf("X25519 handshake failed: %v", err)
		return
	}

	secretPQ, err := internal.PerformHandshakePQ(conn, false)
	if err != nil {
		log.Printf("ML-KEM handshake failed: %v", err)
		return
	}

	sessionKey, err := internal.DeriveHybridSessionKey(secretClassic, secretPQ)
	if err != nil {
		log.Printf("Session key failed: %v", err)
		return
	}

	fmt.Println("Secure session established")

	// Read user input and send to server
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}

		message := scanner.Text()

		// Encrypt message
		ciphertext, err := internal.Encrypt(sessionKey[:], []byte(message))
		if err != nil {
			log.Printf("Encryption failed: %v", err)
			continue
		}

		// Send message to server
		_, err = conn.Write(ciphertext)
		if err != nil {
			log.Printf("Write error: %v", err)
			return
		}

		// Wait for server's response
		response := make([]byte, 1024)
		n, err := conn.Read(response)
		if err != nil {
			log.Printf("Error receiving response: %v", err)
			return
		}

		// Decrypt Response
		decryptedResponse, err := internal.Decrypt(sessionKey[:], response[:n])
		if err != nil {
			fmt.Println("Decryption error:", err)
			continue
		}

		fmt.Printf("Server Response: %s\n", decryptedResponse)
	}
}
