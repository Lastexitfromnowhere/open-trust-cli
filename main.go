package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"open-trust/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		// flag.ErrHelp is returned when --help is passed; not an error condition.
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
