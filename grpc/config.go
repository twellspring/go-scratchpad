package main

import (
	"gopkg.in/yaml.v3"
	"io/ioutil"
)

type Config struct {
	Alb struct {
		Url string
	}
	Auth struct {
		Username string
		Password string
	}

	Userpool struct {
		PoolId       string
		ClientId     string
		ClientSecret string
		Redirect     string
	}
}

func getConfig() Config {
	var cfg Config
	f, err := ioutil.ReadFile("config.yaml")
	processError(err)

	err = yaml.Unmarshal(f, &cfg)
	processError(err)

	return cfg
}
