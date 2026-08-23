//go:build windows

package main

// Windows service wrapper. The installer registers theta-agent as a SYSTEM
// auto-start service; when the SCM launches the process this file takes over.
// The service is up before any user session, which is what allows the
// credential provider to validate LDAP logins at Ctrl+Alt+Del and what makes
// the tray IPC socket path (shared data dir) correct.

import (
	"log"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/svc"
)

// maybeRunAsService returns true (and runs the service loop) when launched by
// the Service Control Manager; false when run in a console.
func maybeRunAsService() bool {
	isSvc, err := svc.IsWindowsService()
	if err != nil || !isSvc {
		return false
	}
	// A service has no stderr: without this, every startup error
	// (log.Fatalf in runAgent included) vanishes and the only symptom is a
	// tray that retries its socket forever. Log to the shared data dir so
	// failures are diagnosable on the box.
	if f, err := os.OpenFile(filepath.Join(windowsDataDir(), "agent.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
		log.SetOutput(f)
		defer f.Close()
	}
	if err := svc.Run("theta-agent", &agentService{}); err != nil {
		log.Printf("service: %v", err)
		os.Exit(1)
	}
	return true
}

type agentService struct{}

func (s *agentService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}

	done := make(chan struct{})
	go func() {
		defer close(done)
		runAgent()
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				stopAgent()
				<-done
				changes <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		case <-done:
			changes <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
}
