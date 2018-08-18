package main

import (
	"fmt"
	"os"
)

func errorOut(msg string) {
	fmt.Printf("error: %s\n", msg)
	os.Exit(-1)
}

func warnOut(msg string) {
	fmt.Printf("warning: %s\n", msg)
}
