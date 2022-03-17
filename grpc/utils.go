package main

import (
	"fmt"
	"os"
)

func processError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
}
