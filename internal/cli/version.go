package cli

import (
	"context"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

func init() {
	Register(Command{
		Name:    "version",
		Group:   "General",
		Summary: "print the version, Go version and VCS revision",
		Usage:   "version",
		Run:     runVersion,
	})
}

func runVersion(_ context.Context, env *Env, args []string) int {
	if len(args) > 0 && args[0] != "-h" && args[0] != "--help" {
		return env.Fail(Usagef("version takes no arguments"))
	}
	version := env.Version
	bi, hasBI := debug.ReadBuildInfo()
	if (version == "" || version == "dev") && hasBI && isReleaseVersion(bi.Main.Version) {
		version = bi.Main.Version
	}
	if version == "" {
		version = "dev"
	}
	var b []byte
	b = fmt.Appendf(b, "sipcurious %s\n%s %s/%s\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	if hasBI {
		var rev, when, dirty string
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.time":
				when = s.Value
			case "vcs.modified":
				if s.Value == "true" {
					dirty = " (modified)"
				}
			}
		}
		if rev != "" {
			b = fmt.Appendf(b, "commit %s%s %s\n", rev, dirty, when)
		}
	}
	_, err := env.Stdout.Write(b)
	return env.Fail(err)
}

// isReleaseVersion reports a clean module version such as v2.1.0, as set by
// "go install ...@v2.1.0"; pseudo-versions and "(devel)" are not releases.
func isReleaseVersion(v string) bool {
	return strings.HasPrefix(v, "v") && !strings.HasPrefix(v, "v0.0.0-") && !strings.Contains(v, "+dirty")
}
