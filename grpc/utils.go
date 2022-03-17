package main

import (
	"fmt"
	"net/http"
	"os"
)

func httpClient(redCount int) *http.Client {
	loop := 0
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if loop >= redCount {
				return http.ErrUseLastResponse
			} else {
				loop += 1
				printRequest(req)
				return nil
			}
		},
	}
	return client
}

func processError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
}

func printRequest(req *http.Request) {
	fmt.Printf("REQUEST: %s %s\n", req.Method, req.URL)
}
