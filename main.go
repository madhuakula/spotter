//go:build !wasm

package main

import (
	"github.com/madhuakula/spotter/cmd"
)

func main() {

	cmd.Execute()
}
