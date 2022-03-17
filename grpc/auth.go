package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	cognito "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/gorilla/schema"
	"io"
	"net/http"
	"net/url"
	"strings"
)

var decode = schema.NewDecoder()

type App struct {
	CognitoClient   *cognito.CognitoIdentityProvider
	UserPoolID      string
	AppClientID     string
	AppClientSecret string
}

type User struct {
	Username string
	Password string
}

type Query struct {
	Response_type string
	Scope         string
	State         string
	Client_id     string
	Redirect_uri  string
}

func browserHeaders(req *http.Request) *http.Request {
	rawHeaders := `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
accept-encoding: gzip, deflate, br
accept-language: en-US,en;q=0.9
sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="99", "Google Chrome";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "macOS"
sec-fetch-dest: document
sec-fetch-mode: navigate
sec-fetch-site: none
sec-fetch-user: ?1
upgrade-insecure-requests: 1
user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36
`
	for _, line := range strings.Split(strings.TrimSuffix(rawHeaders, "\n"), "\n") {
		split := strings.Split(line, ":")
		req.Header.Add(split[0], strings.TrimSpace(split[1]))
	}
	return req
}

func computeSecretHash(clientSecret string, username string, clientId string) string {
	mac := hmac.New(sha256.New, []byte(clientSecret))
	mac.Write([]byte(username + clientId))

	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func initialRedirect(config Config, client *http.Client) {
	// go to ALB and get redirected to login
	req, err := http.NewRequest("GET", config.Alb.Url, nil)
	req = browserHeaders(req)
	fmt.Printf("DO: %s\n", req.URL)
	resp, err := client.Do(req)
	processError(err)

	// get csrf out of XSRF-TOKEN cookie
	// TODO loop cookies and search for XSRF-TOKEN in case there are more than one cookies_
	cookie := resp.Header["Set-Cookie"][0]
	csrf := strings.Split(strings.Split(cookie, ";")[0], "=")[1]

	//Post to login URL and allow 1 redirect (to idp that returns AWSELB Auth Session Cookies)
	data := url.Values{}
	data.Set("_csrf", csrf)
	data.Set("username", config.Auth.Username)
	data.Set("password", config.Auth.Password)

	req, err = http.NewRequest("POST", resp.Request.URL.String(), strings.NewReader(data.Encode()))
	//req = browserHeaders(req)
	//req.Header.Add("authority", "auth.baseplatform2.irondev.io")
	//req.Header.Add("cache-control", "max-age-0")
	//req.Header.Add("origin", "https://auth.baseplatform2.irondev.io")
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	//req.Header.Add("sec-fetch-site", "same-origin")
	//req.Header.Add("sec-fetch-mode", "navigate")
	//req.Header.Add("sec-fetch-user", "?1")
	//req.Header.Add("sec-fetch-dest", "document")
	//req.Header.Add("referer", "https://auth.baseplatform2.irondev.io/login?client_id=o8ned9b7gdmcu9qhth0bmelkp&redirect_uri=https%3A%2F%2Fmn-ook.baseplatform2.irondev.io%2Foauth2%2Fidpresponse&response_type=code&scope=openid&state=m5XCN%2BeCXx3MmqsRcmWG3BKzD%2FUv%2FivOoZheil0zyghxl6%2Bp1r9PTYx7Oty4HTlAh5wCls7J%2BKvjv74fxfz7MZCRO2prMYPKZaoFDIKYEGLtTx9tQ4bti4WhHXNKat7EkAIN47EwrRgAce%2Bbe7%2B6o7T%2BrB7r1FK2hVRYrn9nx9WhaNBDL5aJDqocmOi9bHFihYeRFVHIfmgQy0vgUlw%3D")
	//req.Header.Add("accept-language", "en-US,en;q=0.9")
	req.Header.Add("cookie", cookie)


	fmt.Printf("DO: %s\n", req.URL)
	loop := 0
	client = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if loop >= 1 {
				fmt.Printf("Exit beofre URL %s", req.URL.String())
				return http.ErrUseLastResponse
			} else {
				loop += 1
				fmt.Printf("REDIRECT: %s\n", req.URL.String())
				fmt.Printf("REQ HEADERS: %s\n", req.Header)
				fmt.Printf("RESPONSE HEADERS: %s\n", req.Response.Header)
				return nil
			}

		},
	}
	res, err := client.Do(req)
	processError(err)

	// Go to ALB URL and add  AWSELB Auth Session Cookies.
	// For some reason these cookies are not added to the login 2nd redirect to ALB URL so doing it manually
	fmt.Printf("\n\nURL: %s\n", res.Header["Location"][0])
	req, err = http.NewRequest("GET", res.Header["Location"][0], nil)
	for _, cookie := range res.Cookies() {
		req.AddCookie(cookie)
	}

	client = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	res, err = client.Do(req)
	processError(err)

	fmt.Printf("URL: %s\n", req.URL.String())
	fmt.Printf("STATUS: %s\n", res.Status)
	fmt.Printf("REQ HEADERS: %s\n", req.Header)
	fmt.Printf("RESPONSE HEADERS: %s\n", res.Header)
	bodyByte, _ := io.ReadAll(res.Body)
	body := string(bodyByte)
	fmt.Printf("BODY: \n%s", body)
}

TODO
- Make a httpClient method that will return a client that can accept a variable number of redirects
- clean up code

func main() {
	config := getConfig()
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			//fmt.Printf("REDIRECT: %s\n", req.URL.String())
			//fmt.Printf("REQ HEADERS: %s\n", req.Header)
			//fmt.Printf("RESPONSE HEADERS: %s\n", req.Response.Header)

			return nil
		},
	}
	//client := &http.Client{}
	initialRedirect(config, client)

	//curl 'https://auth.baseplatform2.irondev.io/login?
	//	XXX client_id=o8ned9b7gdmcu9qhth0bmelkp&
	//	XXXX redirect_uri=https%3A%2F%2Fmn-ook.baseplatform2.irondev.io%2Foauth2%2Fidpresponse&
	//	XXX response_type=code&
	//	XXX scope=openid&
	//	XXX state=m5XCN%2BeCXx3MmqsRcmWG3BKzD%2FUv%2FivOoZheil0zyghxl6%2Bp1r9PTYx7Oty4HTlAh5wCls7J%2BKvjv74fxfz7MZCRO2prMYPKZaoFDIKYEGLtTx9tQ4bti4WhHXNKat7EkAIN47EwrRgAce%2Bbe7%2B6o7T%2BrB7r1FK2hVRYrn9nx9WhaNBDL5aJDqocmOi9bHFihYeRFVHIfmgQy0vgUlw%3D' \
	//-H 'authority: auth.baseplatform2.irondev.io' \
	//-H 'cache-control: max-age=0' \
	//-H 'sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="99", "Google Chrome";v="99"' \
	//-H 'sec-ch-ua-mobile: ?0' \
	//-H 'sec-ch-ua-platform: "macOS"' \
	//-H 'upgrade-insecure-requests: 1' \
	//-H 'origin: https://auth.baseplatform2.irondev.io' \
	//-H 'content-type: application/x-www-form-urlencoded' \
	//-H 'user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36' \
	//-H 'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9' \
	//-H 'sec-fetch-site: same-origin' \
	//-H 'sec-fetch-mode: navigate' \
	//-H 'sec-fetch-user: ?1' \
	//-H 'sec-fetch-dest: document' \
	//-H 'referer: https://auth.baseplatform2.irondev.io/login?client_id=o8ned9b7gdmcu9qhth0bmelkp&redirect_uri=https%3A%2F%2Fmn-ook.baseplatform2.irondev.io%2Foauth2%2Fidpresponse&response_type=code&scope=openid&state=m5XCN%2BeCXx3MmqsRcmWG3BKzD%2FUv%2FivOoZheil0zyghxl6%2Bp1r9PTYx7Oty4HTlAh5wCls7J%2BKvjv74fxfz7MZCRO2prMYPKZaoFDIKYEGLtTx9tQ4bti4WhHXNKat7EkAIN47EwrRgAce%2Bbe7%2B6o7T%2BrB7r1FK2hVRYrn9nx9WhaNBDL5aJDqocmOi9bHFihYeRFVHIfmgQy0vgUlw%3D' \
	//-H 'accept-language: en-US,en;q=0.9' \
	//-H 'cookie: XSRF-TOKEN=ead4a066-698e-4cc0-bfcc-000d4e0cb296; csrf-state=""; csrf-state-legacy=""' \
	//--data-raw '_csrf=ead4a066-698e-4cc0-bfcc-000d4e0cb296&username=twells&password=asdfoijgwaerGSDF1%40%21&cognitoAsfData=eyJwYXlsb2FkIjoie1wiY29udGV4dERhdGFcIjp7XCJVc2VyQWdlbnRcIjpcIk1vemlsbGEvNS4wIChNYWNpbnRvc2g7IEludGVsIE1hYyBPUyBYIDEwXzE1XzcpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS85OS4wLjQ4NDQuNTEgU2FmYXJpLzUzNy4zNlwiLFwiRGV2aWNlSWRcIjpcIjY4bGJzYWJnYnBtMWxneTFkYzlmOjE2NDczNjM5OTA0MjFcIixcIkRldmljZUxhbmd1YWdlXCI6XCJlbi1VU1wiLFwiRGV2aWNlRmluZ2VycHJpbnRcIjpcIk1vemlsbGEvNS4wIChNYWNpbnRvc2g7IEludGVsIE1hYyBPUyBYIDEwXzE1XzcpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS85OS4wLjQ4NDQuNTEgU2FmYXJpLzUzNy4zNlBERiBWaWV3ZXI6Q2hyb21lIFBERiBWaWV3ZXI6Q2hyb21pdW0gUERGIFZpZXdlcjpNaWNyb3NvZnQgRWRnZSBQREYgVmlld2VyOldlYktpdCBidWlsdC1pbiBQREY6ZW4tVVNcIixcIkRldmljZVBsYXRmb3JtXCI6XCJNYWNJbnRlbFwiLFwiQ2xpZW50VGltZXpvbmVcIjpcIi0wNzowMFwifSxcInVzZXJuYW1lXCI6XCJ0d2VsbHNcIixcInVzZXJQb29sSWRcIjpcIlwiLFwidGltZXN0YW1wXCI6XCIxNjQ3MzYzOTkwNDIxXCJ9Iiwic2lnbmF0dXJlIjoiajMxaGdZM3BOMGJUb3lhMkQ4clEyNG9hWjVaVEg0SmpOaDdiYTVVRGFyaz0iLCJ2ZXJzaW9uIjoiSlMyMDE3MTExNSJ9&signInSubmitButton=Sign+in' \
	//--compressed

	//resp, err := client.Post(config.Alb.Url)
	//processError(err)
	//fmt.Printf("Status: %s\nLocation: %s", resp.Status, resp.Header["Location"][0])
	//bodyByte, _ := io.ReadAll(resp.Body)
	//body := string(bodyByte)
	//fmt.Println(body)

	//ses, _ := session.NewSession(&aws.Config{Region: aws.String("us-east-2")})
	//secretHash := computeSecretHash(config.Userpool.ClientSecret, config.Auth.Username, config.Userpool.ClientId)
	//authTry := &cognito.InitiateAuthInput{
	//	AuthFlow: aws.String("USER_PASSWORD_AUTH"),
	//	AuthParameters: map[string]*string{
	//		"USERNAME":    aws.String(config.Auth.Username),
	//		"PASSWORD":    aws.String(config.Auth.Password),
	//		"SECRET_HASH": aws.String(secretHash),
	//	},
	//	ClientId: aws.String(config.Userpool.ClientId),
	//}
	//
	//cognitoClient := cognitoidentityprovider.New(ses)
	//authResp, err := cognitoClient.InitiateAuth(authTry)
	//processError(err)
	//
	//fmt.Println("got here")
	//fmt.Println(authResp)
	//// Looking at https://hadleybradley.com/technical/aws-cognito.html

	// print body contents
	//bodyByte, _ := io.ReadAll(resp.Body)
	//body := string(bodyByte)
	//fmt.Println(body)

	// decompose url
	//u, err := url.Parse(resp.Header["Location"][0])
	//var query Query
	//err = decode.Decode(&query, u.Query())
	//rUrl := fmt.Sprintf("%s://%s/login", u.Scheme, u.Host)
	//fmt.Println(rUrl)
	//fmt.Printf("%+v\n", query)
	//fmt.Println(resp.Header)
}

//
//IDP Auth get grant code
//Load Balancer with grant code
