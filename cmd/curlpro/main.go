// Command curlpro provides the profile maintenance tools.
//
//	curlpro validate   run profiles through an oracle and compare fingerprints
//	curlpro diff       compare two profiles field by field
//	curlpro list       list the profiles
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "capture":
		err = runCapture(os.Args[2:])
	case "collapse":
		err = runCollapse(os.Args[2:])
	case "validate":
		err = runValidate(os.Args[2:])
	case "diff":
		err = runDiff(os.Args[2:])
	case "list":
		err = runList(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `curlpro — profile maintenance tools

  capture    capture a browser fingerprint and build a profile
  collapse   fold profiles into based_on chains, keeping only the differences
  validate   run profiles through an oracle and compare with the baseline
  diff       compare two profiles by extensions and settings
  list       list the profiles

Details: curlpro <command> -h
`)
}

// newFlagSet creates a flag set with the command description in its help.
func newFlagSet(name, description string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, description)
		fs.PrintDefaults()
	}
	return fs
}
