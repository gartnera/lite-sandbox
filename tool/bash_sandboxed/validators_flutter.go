package bash_sandboxed

import (
	"fmt"

	"mvdan.cc/sh/v3/syntax"
)

// flutterRuntimeEnabled reports whether the Flutter/Dart/fvm runtime is enabled
// in the current config.
func (s *Sandbox) flutterRuntimeEnabled() bool {
	cfg := s.getConfig()
	return cfg.Runtimes != nil && cfg.Runtimes.Flutter.FlutterEnabled()
}

// validateFlutterCommand gates the flutter binary behind the Flutter runtime.
// flutter is a code-execution runtime (like go/cargo/deno): its containment
// relies on the OS sandbox rather than argument validation, so once the runtime
// is enabled all subcommands are permitted. The paths flutter reads and writes
// (SDK cache, pub cache, config dirs) are made accessible via detectFlutterBinds.
func validateFlutterCommand(s *Sandbox, args []*syntax.Word) error {
	return flutterCommandGate(s, "flutter")
}

// validateDartCommand gates the dart binary behind the Flutter runtime. dart is
// bundled with the Flutter SDK and shares the same caches, so it is enabled by
// the same config switch.
func validateDartCommand(s *Sandbox, args []*syntax.Word) error {
	return flutterCommandGate(s, "dart")
}

// validateFvmCommand gates the fvm (Flutter Version Management) wrapper behind
// the Flutter runtime. fvm proxies flutter/dart against a selected SDK version
// from its cache; that cache is made accessible via detectFlutterBinds.
func validateFvmCommand(s *Sandbox, args []*syntax.Word) error {
	return flutterCommandGate(s, "fvm")
}

// flutterCommandGate returns an error unless the Flutter runtime is enabled.
func flutterCommandGate(s *Sandbox, name string) error {
	if !s.flutterRuntimeEnabled() {
		return fmt.Errorf("command %q is not allowed (runtimes.flutter.enabled is disabled)", name)
	}
	return nil
}
