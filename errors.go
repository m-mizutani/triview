package main

import "github.com/m-mizutani/goerr"

var (
	errInvalidDatabase  = goerr.New("Invalid trivy DB")
	errResourceNotFound = goerr.New("Resource not found")
)
