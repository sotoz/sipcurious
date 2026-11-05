package cli

import (
	"context"
	"fmt"

	"github.com/sotoz/sipcurious/internal/query"
)

func init() {
	Register(Command{
		Name:    "fields",
		Group:   "Reference",
		Summary: "print the filter language and the fields usable in --where",
		Usage:   "fields",
		Run: func(_ context.Context, env *Env, args []string) int {
			if len(args) > 0 && args[0] != "-h" && args[0] != "--help" {
				return env.Fail(Usagef("fields takes no arguments"))
			}
			_, err := fmt.Fprint(env.Stdout, query.Help())
			return env.Fail(err)
		},
	})
}
