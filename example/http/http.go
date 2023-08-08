package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
)

func main() {
	if err := run(os.Args[0:]...); err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args ...string) error {
	router := chi.NewRouter()

	router.Get("/auth/default", func(w http.ResponseWriter, r *http.Request) {

	})

	return nil
}
