//go:build !wasm

package main

import (
	"github.com/madhuakula/spotter/cmd"
)

func main() {
	// Built-in rules are now loaded via API instead of embedded filesystem
	cmd.Execute()
}
