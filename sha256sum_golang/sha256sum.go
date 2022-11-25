package main

import (
    "fmt"
    "github.com/sha256_golang"
)

func main() {
    msg, _ := sha256_golang.Hello("world")
    fmt.Println(msg)
}
