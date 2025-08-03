package main

import (
	"github.com/madhuakula/spotter/cmd"
	"github.com/madhuakula/spotter/internal"
)

func main() {
	// Initialize built-in rules filesystem for cmd package
	cmd.BuiltinRulesFS = internal.BuiltinRules

	cmd.Execute()
}
