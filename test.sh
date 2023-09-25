#!/bin/bash
mv go.mod .go.mod
mv go_test.mod go.mod

go test $@ 

mv go.mod go_test.mod
mv .go.mod go.mod
