package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	"github.com/fahmifan/authme/integration/httpserver"
	_ "github.com/lib/pq"
)

func main() {
	db, err := sql.Open("postgres", "postgres://root:root@localhost:5432/authme?sslmode=disable")
	if err != nil {
		panic(err)
	}

	stopChan := make(chan os.Signal, 1)
	go func() {
		if err := httpserver.RunPSQLBackend(db); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}()
	fmt.Println("Server running on http://localhost:8080")
	<-stopChan
	httpserver.Stop(context.TODO())
}
