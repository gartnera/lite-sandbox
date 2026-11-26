package bash_sandboxed

// The incus and lxc CLIs (cobra/pflag) as far as the path checks need them.
// The daemon is reached through the incus proxy, which enforces the policy on
// the wire (internal/incusproxy); here only the words that are or are not
// host paths matter. Most subcommands name instances, images and in-instance
// paths, which the generic check would read as host paths: `incus exec c1 --
// cat /etc/hostname` runs in the instance and names no host file. The host
// files are the sources of `file push` (read, left to the generic check) and
// the targets of `file pull`, `export` and `image export` (written).

// incusOpts lists the options with values of the global flags and of the
// subcommands declared below, from `incus <subcommand> --help` (lxc's match),
// so their values are not read as operands.
var incusOpts = optSpec{
	long: []string{
		"project",                             // global
		"env", "mode", "user", "group", "cwd", // exec
		"uid", "gid", // file push (with mode)
		"compression", // export
	},
	flags: []string{
		"version", "help", "force-local", "debug", "verbose", "quiet", "sub-commands", "explain",
		"force-interactive", "force-noninteractive", "disable-stdin",
		"create-dirs", "recursive",
		"instance-only", "optimized-storage", "vm",
	},
}

// incusRoles returns the non-path words and the written words of an incus or
// lxc command line.
func incusRoles(args []string) (nonPath map[int]bool, writes []int) {
	p := incusOpts.scan(args)
	ops := p.operands
	word := func(k int) string {
		if k < len(ops) {
			return args[ops[k]]
		}
		return ""
	}
	nonPath = map[int]bool{}
	switch word(0) {
	case "exec":
		// Everything is the instance's: its name, the in-instance command
		// and its --cwd and --env values.
		for i := 1; i < len(args); i++ {
			nonPath[i] = true
		}
	case "file":
		switch word(1) {
		case "pull":
			// <instance>/<path>... <target path>
			if len(ops) >= 4 {
				for _, i := range ops[2 : len(ops)-1] {
					nonPath[i] = true
				}
				writes = append(writes, ops[len(ops)-1])
			}
		case "push":
			// <source path>... <instance>/<path>
			if len(ops) >= 4 {
				nonPath[ops[len(ops)-1]] = true
			}
		}
	case "export":
		// <instance> [target]
		if len(ops) >= 2 {
			nonPath[ops[1]] = true
		}
		if len(ops) >= 3 {
			writes = append(writes, ops[2])
		}
	case "image":
		if word(1) == "export" {
			// <image> [target]
			if len(ops) >= 3 {
				nonPath[ops[2]] = true
			}
			if len(ops) >= 4 {
				writes = append(writes, ops[3])
			}
		}
	}
	return nonPath, writes
}

func incusNonPathArgs(args []string) map[int]bool {
	nonPath, _ := incusRoles(args)
	return nonPath
}

func incusWriteTargets(args []string, _ map[int]bool) []string {
	_, writes := incusRoles(args)
	var out []string
	for _, i := range writes {
		out = append(out, args[i])
	}
	return out
}
