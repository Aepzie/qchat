//go:build windows

package main

import (
	"context"
	"time"

	"golang.org/x/sys/windows/svc"
)

// serviceStopWaitHint tells the service manager how long a stop may take:
// a graceful shutdown is bounded by about 15 seconds.
const serviceStopWaitHint = 20 * time.Second

// serviceExitFailure is the service-specific exit code reported when the
// server stops because of an error.
const serviceExitFailure = 1

// runAsService runs serve under the Windows service control manager if the
// process was started as a service. It reports whether that was the case;
// when it was not, the caller runs serve in the foreground.
func runAsService(serve func(context.Context) error) (bool, error) {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false, nil
	}
	handler := &serviceHandler{serve: serve}
	if err := svc.Run(programName, handler); err != nil {
		return true, err
	}
	return true, handler.err
}

// serviceHandler maps service control requests to context cancellation.
type serviceHandler struct {
	serve func(context.Context) error
	err   error
}

// Execute implements svc.Handler.
func (h *serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.serve(ctx) }()

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	stopping := false
	for {
		select {
		case err := <-done:
			return h.finish(err, status)
		case req := <-requests:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				if stopping {
					continue
				}
				stopping = true
				status <- svc.Status{State: svc.StopPending, WaitHint: uint32(serviceStopWaitHint / time.Millisecond)}
				cancel()
			}
		}
	}
}

// finish records the outcome and reports StopPending; the svc package
// reports Stopped with the returned exit code once Execute returns.
func (h *serviceHandler) finish(err error, status chan<- svc.Status) (bool, uint32) {
	h.err = err
	status <- svc.Status{State: svc.StopPending}
	if err != nil {
		return true, serviceExitFailure
	}
	return false, 0
}
