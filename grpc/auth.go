package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

var sesCookies Cookies
var onlyOnce sync.Once

type Cookies struct {
	SessionCookie0 http.Cookie
	SessionCookie1 http.Cookie
}

func requiredCookies(req *http.Request) bool {
	required := map[string]bool{
		"AWSELBAuthSessionCookie-0": false,
		"AWSELBAuthSessionCookie-1": false,
	}
	for _, cookie := range req.Cookies() {
		delete(required, cookie.Name)
	}
	if len(required) == 0 {
		return true
	}
	return false
}

func addCookies(req *http.Request, config Config) {
	onlyOnce.Do(func() {
		cookies := getCookies(config)
		sesCookies.SessionCookie0 = *cookies[0]
		sesCookies.SessionCookie1 = *cookies[1]
	})
	req.AddCookie(&sesCookies.SessionCookie0)
	req.AddCookie(&sesCookies.SessionCookie1)
}

func getCookies(config Config) []*http.Cookie {
	fmt.Printf("Do Auth and get ALB Session Cookies\n")
	// go to ALB and get redirected to login
	req, err := http.NewRequest("GET", config.Alb.Url, nil)
	client := httpClient(99)
	printRequest(req)
	resp, err := client.Do(req)
	processError(err)

	// get csrf out of XSRF-TOKEN cookie
	var csrf string
	var cookie string
	for _, c := range resp.Header["Set-Cookie"] {
		if strings.HasPrefix(c, "XSRF-TOKEN=") {
			fmt.Printf("Found XSRF-TOKEN %s\n", cookie)
			csrf = strings.Split(strings.Split(c, ";")[0], "=")[1]
			cookie = c
		}
	}

	//Post to login URL and allow 1 redirect (to idp that returns AWSELB Auth Session Cookies)
	qp := url.Values{}
	qp.Set("_csrf", csrf)
	qp.Set("username", config.Auth.Username)
	qp.Set("password", config.Auth.Password)
	req, err = http.NewRequest("POST", resp.Request.URL.String(), strings.NewReader(qp.Encode()))
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	req.Header.Add("cookie", cookie)
	client = httpClient(1)
	printRequest(req)
	res, err := client.Do(req)
	processError(err)
	return res.Cookies()
}
