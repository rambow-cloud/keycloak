package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestOperatorArguments(t *testing.T) {
	cases := [][]string{
		{"-Djgroups.bind.address=10.244.0.2", "--verbose", "start", "--optimized"},
		{"--verbose", "import", "--file=/mnt/realm with spaces.json", "--override=false"},
		{"update-compatibility", "metadata", "--file", "/mnt/updates.json", "-Djgroups.bind.address=10.244.0.2", "--verbose", "--optimized"},
		{"update-compatibility", "check", "--file=/mnt/updates.json"},
	}
	for _, input := range cases {
		arguments, err := javaArguments(input, 42)
		if err != nil { t.Fatal(err) }
		main := -1
		for index, argument := range arguments { if argument == "io.quarkus.bootstrap.runner.QuarkusEntryPoint" { main = index } }
		if main < 0 { t.Fatal("missing launcher class") }
		for index, argument := range arguments { if strings.HasPrefix(argument, "-D") && index > main { t.Fatal("JVM property reached the application") } }
		if arguments[len(arguments)-1] != "--optimized" { t.Fatal("prebuilt mode missing") }
		if !strings.Contains(strings.Join(arguments, "|"), "-Dkc.script.pid=42") { t.Fatal("wrong process identity") }
	}
}

func TestBoundariesAndLiteralArguments(t *testing.T) {
	for _, input := range [][]string{{"build"},{"start-dev"},{"export"},{"-D"},{"-D=x"},{"start","--optimized=false"},{"start","--optimized","false"},{"update-compatibility","invalid"},{"start","--auto-build"}} {
		if _, err := javaArguments(input, 1); err == nil { t.Fatalf("accepted forbidden command shape: %q", input) }
	}
	for _, input := range [][]string{nil,{"--version"},{"--help"},{"--verbose","start","--optimized=true"}} {
		if _, err := javaArguments(input, 1); err != nil { t.Fatal(err) }
	}
	literal := "-Dexample=a b;$(touch /tmp/must-not-execute)\"é"
	arguments, err := javaArguments([]string{literal,"import","--file=/a b.json"}, 1)
	if err != nil { t.Fatal(err) }
	if arguments[3] != literal { t.Fatal("property was split or evaluated") }
	if !reflect.DeepEqual(arguments[len(arguments)-3:], []string{"import","--file=/a b.json","--optimized"}) { t.Fatal("application boundaries changed") }
	arguments, err = javaArguments([]string{"start","--","-Dliteral=value"}, 1)
	if err != nil { t.Fatal(err) }
	if arguments[len(arguments)-2] != "-Dliteral=value" { t.Fatal("literal suffix was reclassified") }
}

func init() {
	if os.Getenv("KC_TEST_EXEC_CAPTURE") == "1" {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"pid":os.Getpid(),"argv":os.Args})
		os.Exit(23)
	}
}

func TestExecReplacesProcessAndPreservesExit(t *testing.T) {
	if os.Getenv("KC_TEST_EXEC_REPLACE") == "1" {
		pid := os.Getpid()
		os.Setenv("KC_TEST_EXEC_CAPTURE", "1")
		if err := execute(os.Args[0], []string{"native-test", strconv.Itoa(pid), "space ; $ literal"}); err != nil { os.Exit(99) }
		os.Exit(98)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestExecReplacesProcessAndPreservesExit$")
	command.Env = append(os.Environ(), "KC_TEST_EXEC_REPLACE=1")
	output, err := command.Output()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 23 { t.Fatalf("exec exit was changed: %v", err) }
	var actual struct {PID int `json:"pid"`; Argv []string `json:"argv"`}
	if json.Unmarshal(output, &actual) != nil { t.Fatal("invalid capture") }
	if strconv.Itoa(actual.PID) != actual.Argv[1] || actual.Argv[2] != "space ; $ literal" { t.Fatal("process identity or argv changed") }
}
