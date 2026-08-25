package main

// Service lifecycle control, dispatched by service subtype.
//
// The Directory offers start/stop/restart on a registered service resource,
// and the agent registers services of several kinds -- systemd units, docker
// and podman containers, OpenRC services. They were all sent to
// `systemctl <action> <name>`, which is right for exactly one of them:
// restarting a docker container through systemctl targets a unit that does not
// exist, and the failure surfaces as an unexplained non-zero exit rather than
// as anything the operator can act on.
//
// The action is also allowlisted here rather than passed through. ServiceControl
// interpolates it straight into an argv, so an unconstrained string from the
// wire is an argument-injection surface -- signature verification makes it hard
// to reach, but "hard to reach" is not the same as "closed".

import (
	"fmt"
	"sort"
	"strings"
)

// serviceExecutor runs the container/OpenRC tools. A package-level seam,
// mirroring defaultPlatformOps, so command dispatch can be exercised without
// docker or rc-service being installed on the test machine.
var serviceExecutor Executor = &SystemExecutor{}

// serviceActions are the verbs a service resource may be sent. `status` is
// read-only and is the one the Directory polls without a signature.
var serviceActions = map[string]bool{
	"start":   true,
	"stop":    true,
	"restart": true,
	"reload":  true,
	"status":  true,
}

func serviceActionList() string {
	names := make([]string, 0, len(serviceActions))
	for a := range serviceActions {
		names = append(names, a)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// containerActions maps a service verb onto the container-runtime verb. docker
// and podman have no `reload`; the closest honest equivalent is a restart, but
// silently substituting one for the other would surprise the caller, so reload
// is refused for containers instead.
var containerActions = map[string]string{
	"start":   "start",
	"stop":    "stop",
	"restart": "restart",
	"status":  "inspect",
}

// controlService runs `action` against `service`, choosing the tool from the
// subtype the Directory recorded for that resource. An empty or unknown subtype
// means systemd, which is what every pre-subtype resource is.
func controlService(ops PlatformOps, subtype, service, action string) ([]byte, error) {
	if service == "" {
		return nil, fmt.Errorf("service name required")
	}
	if !serviceActions[action] {
		return nil, fmt.Errorf("unsupported service action %q -- use one of: %s", action, serviceActionList())
	}

	switch strings.ToLower(strings.TrimSpace(subtype)) {
	case "docker", "podman":
		runtimeName := strings.ToLower(strings.TrimSpace(subtype))
		verb, ok := containerActions[action]
		if !ok {
			return nil, fmt.Errorf("%s containers have no %q -- use start, stop or restart", runtimeName, action)
		}
		return serviceExecutor.Execute(runtimeName, verb, service)
	case "openrc":
		// OpenRC takes the service first and the verb second, the opposite of
		// systemctl. Getting this backwards is a silent no-op on some
		// installations rather than an error.
		return serviceExecutor.Execute("rc-service", service, action)
	default:
		return ops.ServiceControl(service, action)
	}
}

// subtypeOrSystemd is what to say in a log line for a service whose subtype the
// Directory did not send.
func subtypeOrSystemd(subtype string) string {
	if s := strings.ToLower(strings.TrimSpace(subtype)); s != "" {
		return s
	}
	return "systemd"
}
