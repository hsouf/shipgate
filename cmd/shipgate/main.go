// Command shipgate is a deploy gate that refuses to run code in production
// unless it was authored and approved with physical security keys, verified
// against a trust root that lives outside the code forge.
//
// The CLI uses only the standard library on purpose: a security tool should
// keep its dependency tree small and auditable. Subcommands are dispatched
// from the table in commands.go.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		if !errors.Is(err, errUsage) {
			fmt.Fprintln(os.Stderr, "shipgate:", err)
		}
		os.Exit(1)
	}
}
