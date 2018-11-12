#!/usr/bin/env bash

env GOOS=linux GOARCH=amd64 go build -tags vartime -o drynxLinux *.go