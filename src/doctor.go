package main

/*
	doctor.go

	"zoraxy -doctor": a read-only report on why Zoraxy might not be answering. It never opens the
	database and never binds a port, so it is safe to run next to a live or frozen instance.
	It also holds the systemd readiness plumbing (mod/instance) used by main().
*/

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"imuslab.com/zoraxy/mod/instance"
)

var doctorMode = flag.Bool("doctor", false, "Diagnose this machine and exit: other Zoraxy processes, who holds the database lock, frozen (Ctrl+Z) processes, systemd state and stuck listening ports. Read-only, does not open the database. Exit code 0 healthy, 1 problems found")

// runDoctor prints the report and returns the exit code.
func runDoctor() int {
	ports := []instance.PortSpec{
		{Port: instance.PortFromListenAddr(*webUIPort), Label: "admin (-port)", Required: true},
		{Port: *defaultInboundPort, Label: "HTTPS inbound (-default_inbound_port)"},
		{Port: 80, Label: "HTTP inbound"},
	}
	if *fleetPort != "" {
		ports = append(ports, instance.PortSpec{Port: instance.PortFromListenAddr(*fleetPort), Label: "Fleet node (-fleet_port)", Required: true})
	}
	rep := instance.RunDoctor(instance.DoctorOptions{
		DBPath: *path_database,
		Ports:  ports,
		Unit:   "zoraxy",
		Self:   os.Getpid(),
	}, instance.RealProbe())
	fmt.Print(rep.String())
	return rep.ExitCode()
}

// proxyStartSettled is closed once the first attempt to start the reverse proxy listeners has finished
// (bound or failed, or the proxy is configured not to start), see signalProxyStartSettled.
var (
	proxyStartSettled     = make(chan struct{})
	proxyStartSettledOnce sync.Once
)

func signalProxyStartSettled() {
	proxyStartSettledOnce.Do(func() { close(proxyStartSettled) })
}

// announceReady tells systemd (Type=notify) that Zoraxy is up. Call it once the admin listener is bound,
// just before serving it. READY=1 is held back until the reverse proxy has also finished its first
// attempt to bind (so "active" means the ports are really open), but never longer than 60 seconds.
// A no-op when NOTIFY_SOCKET is unset.
func announceReady(adminAddr string) {
	if !instance.NotifyEnabled() {
		return
	}
	go func() {
		settled := true
		select {
		case <-proxyStartSettled:
		case <-time.After(60 * time.Second):
			settled = false
		}
		status := "Admin listening on " + adminAddr
		switch {
		case !settled:
			status += "; reverse proxy still starting"
		case dynamicProxyRouter == nil || !dynamicProxyRouter.Running:
			status += "; reverse proxy not started (disabled in settings)"
		case dynamicProxyRouter.ListenError() != "":
			status += "; WARNING reverse proxy could not bind its port: " + dynamicProxyRouter.ListenError()
		default:
			status += "; reverse proxy listening on port " + strconv.Itoa(dynamicProxyRouter.Option.Port)
		}
		instance.NotifyReady(status)
	}()
}
