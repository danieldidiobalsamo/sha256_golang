// This package is an example of usage for github.com/sha256_golang package
package main

import (
    "fmt"
    "os"

    "github.com/danieldidiobalsamo/sha256_golang/sha256_algo"
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

    hash := sha256_algo.Sha256(body)
    fmt.Printf("%v %v\n", hash, filePath)
}
