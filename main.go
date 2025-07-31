package main

import "github.com/madhuakula/spotter/cmd"

func main() {
	// Initialize built-in rules filesystem for cmd package
	cmd.BuiltinRulesFS = BuiltinRules

	cmd.Execute()
}
