package main

import (
    "fmt"
    "os"

    "github.com/sha256_golang"
)

func main() {

    if len(os.Args) != 2 {
        fmt.Println("Usage: sha256_golang <filepath>")
        return
    }

    filePath := os.Args[1]

    body, err := os.ReadFile(filePath)
    if err != nil {
        fmt.Println(err)
        return
    }

    hash := sha256_golang.Sha256(body)
    fmt.Printf("%v %v", hash, filePath)
}
