package main

import (
	"time"

	"github.com/Eklund2012/pq-hybrid-kex/cmd/client"
	"github.com/Eklund2012/pq-hybrid-kex/cmd/server"
)

func main() {
	// Start server in background
	go server.StartServer()

	// Give server a moment to start
	time.Sleep(time.Second)

	// Launch client
	client.StartClient()
}
