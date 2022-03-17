package main

import (
	"fmt"
	"io"
	"net/http"
)

func doRequest(req *http.Request, config Config) *http.Response {
	if !requiredCookies(req) {
		addCookies(req, config)
	}
	client := httpClient(0)
	printRequest(req)
	res, err := client.Do(req)
	processError(err)
	return res
}

func main() {
	config := getConfig()

	fmt.Println("START First Request")
	req, _ := http.NewRequest("GET", config.Alb.Url, nil)
	res := doRequest(req, config)
	bodyByte, _ := io.ReadAll(res.Body)
	body := string(bodyByte)
	fmt.Println(body)
	fmt.Println("END FirstRequest")

	fmt.Println("START Second Request")
	req, _ = http.NewRequest("GET", config.Alb.Url, nil)
	res = doRequest(req, config)
	fmt.Printf("Second Response RC: %s\n", res.Status)
	fmt.Println("START Second Request")
}
