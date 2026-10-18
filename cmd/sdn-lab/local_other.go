//go:build !linux

package main

import "errors"

func newLocalEnv(localOptions) (Env, error) {
	return nil, errors.New("the local environment runs on Linux only; use --env aws")
}
