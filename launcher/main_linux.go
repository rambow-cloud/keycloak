package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// javaArguments implements the bounded Operator contract, never a shell grammar.
// Input arguments remain distinct argv entries, including spaces and metacharacters.
func javaArguments(input []string, pid int) ([]string, error) {
	var properties, application []string
	literal := false
	for _, argument := range input {
		if argument == "--" {
			literal = true
		}
		if !literal && strings.HasPrefix(argument, "-D") {
			if len(argument) == 2 || argument[2] == '=' {
				return nil, errors.New("invalid JVM property name")
			}
			properties = append(properties, argument)
		} else {
			application = append(application, argument)
		}
	}
	if len(application) == 0 {
		application = []string{"start"}
	}
	command := ""
	position := -1
	for index, argument := range application {
		if !strings.HasPrefix(argument, "-") {
			command, position = argument, index
			break
		}
	}
	help := false
	for _, argument := range application {
		if argument == "--help" || argument == "-h" || argument == "--version" || argument == "-V" {
			help = true
		}
		if argument == "--auto-build" || strings.HasPrefix(argument, "--auto-build=") {
			return nil, errors.New("runtime augmentation is unsupported")
		}
	}
	switch command {
	case "start", "import":
	case "update-compatibility":
		if !help && (position+1 >= len(application) || (application[position+1] != "metadata" && application[position+1] != "check")) {
			return nil, errors.New("unsupported compatibility subcommand")
		}
	case "":
		if !help {
			return nil, errors.New("a supported Keycloak command is required")
		}
	default:
		return nil, errors.New("unsupported Keycloak command; use prebuilt start, import or update-compatibility")
	}
	if command != "" {
		optimized := false
		for index, argument := range application {
			if argument == "--optimized" {
				if index+1 < len(application) && strings.EqualFold(application[index+1], "false") {
					return nil, errors.New("optimized mode cannot be disabled")
				}
				optimized = true
			}
			if strings.HasPrefix(argument, "--optimized=") {
				if !strings.EqualFold(strings.TrimPrefix(argument, "--optimized="), "true") {
					return nil, errors.New("optimized mode cannot be disabled")
				}
				optimized = true
			}
		}
		if !optimized {
			application = append(application, "--optimized")
		}
	}
	arguments := []string{"java", "@/opt/keycloak/java.options", "-Dkc.script.pid=" + strconv.Itoa(pid)}
	arguments = append(arguments, properties...)
	arguments = append(arguments, "-cp", "/opt/keycloak/lib/quarkus-run.jar", "io.quarkus.bootstrap.runner.QuarkusEntryPoint")
	return append(arguments, application...), nil
}

func execute(path string, arguments []string) error {
	return syscall.Exec(path, arguments, os.Environ())
}

func main() {
	arguments, err := javaArguments(os.Args[1:], os.Getpid())
	if err != nil {
		fmt.Fprintln(os.Stderr, "Keycloak launcher:", err)
		os.Exit(2)
	}
	if execute("/usr/bin/java", arguments) != nil {
		// Neither argv nor environment is printed: both may carry credentials.
		fmt.Fprintln(os.Stderr, "Keycloak launcher: unable to execute the JVM")
		os.Exit(127)
	}
}
