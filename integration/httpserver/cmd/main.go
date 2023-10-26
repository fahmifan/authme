package main

import (
	"context"
	"fmt"
	"os"

	"github.com/fahmifan/authme/integration/httpserver"
)

func main() {
	stopChan := make(chan os.Signal, 1)
	go func() {
		if err := httpserver.Run(); err != nil {
			os.Exit(1)
		}
	}()
	fmt.Println("Server running on http://localhost:8080")
	<-stopChan
	httpserver.Stop(context.TODO())
}
