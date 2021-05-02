package main

import (
	"log"
	"os"
)

func main() {
	if err := Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
