package instance

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// PortSpec is a port this configuration expects to serve.
type PortSpec struct {
	Port     int
	Label    string // "admin (-port)", "HTTPS inbound", ...
	Required bool   // a missing listener is a problem (admin port), otherwise just a note (inbound may be disabled)
}

// DoctorOptions describes the configuration being checked.
type DoctorOptions struct {
	DBPath string
	Ports  []PortSpec
	Unit   string // systemd unit name, "zoraxy"
	Self   int    // pid of the doctor process, excluded from the process list
}

// Probe is the set of system readers the doctor uses; tests replace them with fixtures.
type Probe struct {
	LockHolders func(path string) (LockMatch, error)
	Describe    func(pid int) ProcInfo
	ListZoraxy  func(exclude int) ([]ProcInfo, int)
	Sockets     func() ([]ListenSocket, int, error)
	Unit        func(name string) UnitStatus
	OpensFile   func(pid int, path string) (opens, known bool) //nil = cannot tell
	IsRoot      bool
}

// RealProbe reads the live system.
func RealProbe() Probe {
	return Probe{
		LockHolders: FindLockHolders,
		Describe:    Describe,
		ListZoraxy:  ListZoraxyProcesses,
		Sockets:     ListenSockets,
		Unit:        QueryUnit,
		OpensFile:   OpensFile,
		IsRoot:      os.Geteuid() == 0,
	}
}

// Problem is one finding with the commands that fix it.
type Problem struct {
	Text  string
	Steps []string
}

// Report is the doctor's output.
type Report struct {
	Lines    []string
	Problems []Problem
}

// ExitCode is 0 when healthy, 1 when problems were found.
func (r Report) ExitCode() int {
	if len(r.Problems) > 0 {
		return 1
	}
	return 0
}

// String renders the report.
func (r Report) String() string { return strings.Join(r.Lines, "\n") + "\n" }

// Everything that enters the report passes through Sanitize, so no byte that came from another
// process (argv, exe path, cgroup, systemctl) can reach the terminal as an escape sequence.
func (r *Report) addf(format string, a ...any) {
	r.Lines = append(r.Lines, Sanitize(fmt.Sprintf(format, a...)))
}
func (r *Report) problem(text string, steps ...string) {
	for i := range steps {
		steps[i] = Sanitize(steps[i])
	}
	r.Problems = append(r.Problems, Problem{Text: Sanitize(text), Steps: steps})
}

func pidSet(ps []ProcInfo) map[int]bool {
	m := map[int]bool{}
	for _, p := range ps {
		m[p.Pid] = true
	}
	return m
}

// RunDoctor inspects the system without opening the database or binding any port.
func RunDoctor(o DoctorOptions, pr Probe) Report {
	var r Report
	unit := strings.TrimSuffix(o.Unit, ".service")
	if unit == "" {
		unit = "zoraxy"
	}
	r.addf("Zoraxy doctor (read-only: the database is not opened and no port is bound)")
	if !Supported {
		r.addf("")
		r.addf("This platform has no /proc, so processes and sockets cannot be inspected. Nothing was checked.")
		return r
	}
	var cannotSee []string

	// 1. Processes
	procs, unreadable := pr.ListZoraxy(o.Self)
	if unreadable > 0 && !pr.IsRoot {
		cannotSee = append(cannotSee, fmt.Sprintf("%d process(es) of other users (their executable is hidden; run with sudo to see them)", unreadable))
	}
	{ //plugins are children of a Zoraxy and often carry the same name prefix: they are not other instances
		ids := pidSet(procs)
		kept := procs[:0:0]
		for _, p := range procs {
			if !ids[p.PPid] {
				kept = append(kept, p)
			}
		}
		procs = kept
	}
	known := map[int]ProcInfo{}
	for _, p := range procs {
		known[p.Pid] = p
	}

	// 2. Lock holder
	var holders []int
	holderApprox := false
	r.addf("")
	r.addf("Database lock (%s)", o.DBPath)
	m, err := pr.LockHolders(o.DBPath)
	switch {
	case err == ErrNoHolder:
		r.addf("  nobody holds a lock on it")
	case err != nil:
		r.addf("  could not check: %v", err)
	default:
		holderApprox = m.Approximate
		for _, pid := range m.Pids {
			if pid <= 0 {
				cannotSee = append(cannotSee, "a lock holder whose pid the kernel did not report (another pid namespace, or an OFD lock)")
				continue
			}
			holders = append(holders, pid)
			if _, ok := known[pid]; !ok {
				known[pid] = pr.Describe(pid)
			}
			r.addf("  held by %s", known[pid].Describe())
		}
		if m.ViaFdinfo {
			r.addf("  (found through /proc/<pid>/fdinfo of the processes visible to this user; run with sudo to also see other users' processes)")
		}
		if holderApprox {
			r.addf("  (matched by inode only, device numbers differ: treat as likely, not certain)")
		}
	}
	holderSet := map[int]bool{}
	for _, h := range holders {
		holderSet[h] = true
	}

	// 3. Zoraxy processes
	r.addf("")
	r.addf("Zoraxy processes (other than this doctor)")
	all := make([]ProcInfo, 0, len(known))
	for _, p := range known {
		all = append(all, p)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Pid < all[j].Pid })
	if len(all) == 0 {
		r.addf("  none found")
	}
	socks, hidden, sockErr := pr.Sockets()
	socksOf := map[int][]ListenSocket{}
	for _, s := range socks {
		for _, o := range s.Owners {
			socksOf[o] = append(socksOf[o], s)
		}
	}
	zombies := 0
	for _, p := range all {
		if p.Visible && p.State == 'Z' && !holderSet[p.Pid] {
			zombies++ //exited, hold nothing: one summary line instead of a line each
			continue
		}
		tag := ""
		if holderSet[p.Pid] {
			tag = "  [holds the database lock]"
		}
		r.addf("  %s%s", p.Describe(), tag)
		if p.Stopped() {
			s, steps := p.Explain(unit)
			r.problem(s, steps...)
		}
	}
	if zombies > 0 {
		r.addf("  (%d exited Zoraxy process(es) not yet collected by their parent, they hold nothing)", zombies)
	}
	// A process that has the database file open but holds no lock is waiting for the lock holder.
	// Processes whose descriptors we cannot read are counted but never accused.
	runningProcs := 0
	var waiting, unknownDB []string
	for _, p := range all {
		if !p.Visible || p.State == 'Z' {
			continue
		}
		runningProcs++
		if holderSet[p.Pid] || p.Stopped() {
			continue
		}
		if pr.OpensFile == nil {
			unknownDB = append(unknownDB, fmt.Sprintf("PID %d", p.Pid))
			continue
		}
		opens, ok := pr.OpensFile(p.Pid, o.DBPath)
		switch {
		case !ok:
			unknownDB = append(unknownDB, fmt.Sprintf("PID %d", p.Pid))
		case opens && len(holders) > 0:
			waiting = append(waiting, fmt.Sprintf("PID %d", p.Pid))
		}
	}
	if len(waiting) > 0 {
		hp := known[holders[0]]
		txt := fmt.Sprintf("%s has the database open but holds no lock while PID %d holds it: it is most likely blocked waiting for the database lock, which is why a service can show 'active' while serving nothing.", strings.Join(waiting, ", "), hp.Pid)
		r.problem(txt, "Stop the one that should not run (see the list above), then: sudo systemctl restart "+unit)
	} else if runningProcs > 1 && len(holders) == 0 {
		r.addf("  note: %d Zoraxy processes run; none was seen holding %s (other instances may use other databases)", runningProcs, o.DBPath)
	}
	if len(unknownDB) > 0 && !pr.IsRoot {
		cannotSee = append(cannotSee, "whether "+strings.Join(unknownDB, ", ")+" use this database (their descriptors are hidden; run with sudo)")
	}

	// 4. systemd
	r.addf("")
	r.addf("systemd unit %q", unit)
	us := pr.Unit(unit)
	switch {
	case us.TimedOut:
		r.addf("  systemctl did not answer within 4 seconds: systemd itself may be stuck. Skipped.")
	case !us.Available:
		r.addf("  systemctl not available (or systemd is not running): skipped")
	case !us.Exists:
		r.addf("  no such unit (Zoraxy is not installed as a service on this machine)")
	default:
		r.addf("  %s (%s), type=%s, main pid %d", us.Active, us.Sub, us.Type, us.MainPID)
		if us.Fragment != "" {
			r.addf("  unit file %s", us.Fragment)
		}
		active := us.Active == "active" || us.Active == "activating"
		if us.Active == "activating" {
			r.addf("  still starting. With Type=notify it stays 'activating' until Zoraxy reports it is listening; if this lasts long, the start is stuck.")
		}
		if active && us.MainPID > 0 {
			if len(holders) > 0 && !holderSet[us.MainPID] {
				hp := known[holders[0]]
				if hp.Unit != unit+".service" && !hp.Stopped() { //a frozen holder already has its own finding
					_, steps := hp.Explain(unit)
					r.problem(fmt.Sprintf("The service %s is %s (main PID %d) but the database lock is held by %s, which is outside the service. The service cannot work until that one is gone.", unit, us.Active, us.MainPID, hp.Describe()), steps...)
				}
			}
			if _, seen := known[us.MainPID]; !seen && pr.IsRoot {
				known[us.MainPID] = pr.Describe(us.MainPID)
			}
		}
		if us.Active == "active" && us.MainPID > 0 && sockErr == nil && len(socksOf[us.MainPID]) == 0 && (pr.IsRoot || hidden == 0) {
			r.problem(fmt.Sprintf("The service is 'active' but its main process (PID %d) listens on no port. If it never printed 'started', it is waiting on the database lock or on something else during start.", us.MainPID),
				"journalctl -u "+unit+" -n 50 --no-pager", "sudo systemctl restart "+unit)
		}
	}

	// 5. Ports
	r.addf("")
	r.addf("Ports for this configuration")
	if sockErr != nil {
		r.addf("  could not read sockets: %v", sockErr)
	} else {
		if hidden > 0 && !pr.IsRoot {
			cannotSee = append(cannotSee, fmt.Sprintf("the owner of %d listening socket(s) (run with sudo to see all owners)", hidden))
		}
		seenPort := map[int]bool{}
		for _, ps := range o.Ports {
			if ps.Port <= 0 || seenPort[ps.Port] {
				continue
			}
			seenPort[ps.Port] = true
			var on []ListenSocket
			for _, s := range socks {
				if s.Port == ps.Port {
					on = append(on, s)
				}
			}
			if len(on) == 0 {
				if ps.Required && (len(all) > 0 || (us.Active == "active")) {
					r.addf("  %-6d %s: nothing is listening", ps.Port, ps.Label)
					if len(all) > 0 {
						r.problem(fmt.Sprintf("Port %d (%s) has no listener although Zoraxy is running. It may still be starting, or be stuck before it binds.", ps.Port, ps.Label),
							"journalctl -u "+unit+" -n 50 --no-pager")
					}
				} else {
					r.addf("  %-6d %s: not listening (fine if this listener is disabled in the configuration)", ps.Port, ps.Label)
				}
				continue
			}
			for _, s := range on {
				owner := "owner not visible"
				ownerIsZoraxy := false
				if len(s.Owners) > 0 {
					var names []string
					for _, op := range s.Owners {
						if _, ok := known[op]; ok {
							ownerIsZoraxy = true
							names = append(names, fmt.Sprintf("PID %d (%s)", op, known[op].ExeBase()))
						} else {
							d := pr.Describe(op)
							names = append(names, fmt.Sprintf("PID %d (%s)", op, d.ExeBase()))
							if IsZoraxyName(d.ExeBase()) {
								ownerIsZoraxy = true
							}
						}
					}
					owner = strings.Join(names, ", ")
				}
				q := ""
				if s.TxQ > 0 {
					q = fmt.Sprintf(", accept queue %d/%d", s.RxQ, s.TxQ)
				}
				r.addf("  %-6d %s: %s %s%s", ps.Port, ps.Label, s.Addr(), owner, q)
				if s.QueueFull() {
					r.problem(fmt.Sprintf("Port %d: the accept queue is full (%d waiting, limit %d): connections are piling up, nothing is accepting. Browsers get 'connection refused' or time out. The listening process (%s) is frozen or stuck.", ps.Port, s.RxQ, s.TxQ, owner),
						"Find it above (state T = frozen) and run: sudo kill -CONT <pid>  or  sudo kill -9 <pid>")
				}
				if len(s.Owners) > 0 && !ownerIsZoraxy {
					r.problem(fmt.Sprintf("Port %d (%s) is held by %s, not by Zoraxy. Zoraxy cannot bind it.", ps.Port, ps.Label, owner),
						"Stop that program or change Zoraxy's port, then: sudo systemctl restart "+unit)
				}
			}
		}
		// queues of any other socket a Zoraxy owns
		for _, p := range all {
			for _, s := range socksOf[p.Pid] {
				if seenPort[s.Port] {
					continue
				}
				if s.QueueFull() {
					r.problem(fmt.Sprintf("PID %d: the accept queue on %s is full (%d/%d), connections are piling up, nothing is accepting.", p.Pid, s.Addr(), s.RxQ, s.TxQ),
						"sudo kill -CONT "+fmt.Sprint(p.Pid)+"  or  sudo kill -9 "+fmt.Sprint(p.Pid))
				}
			}
		}
	}

	// 6. What we could not see, verdict
	if len(cannotSee) > 0 {
		r.addf("")
		r.addf("Could not see")
		for _, c := range cannotSee {
			r.addf("  - %s", c)
		}
	}
	r.addf("")
	if len(r.Problems) == 0 {
		r.addf("Verdict: healthy. No frozen process, no competing instance, no stuck listener found.")
		if len(cannotSee) > 0 {
			r.addf("(Some things could not be seen, see above; run with sudo for a complete check.)")
		}
		return r
	}
	r.addf("Verdict: %d problem(s) found", len(r.Problems))
	for i, p := range r.Problems {
		r.addf("")
		r.addf("  %d. %s", i+1, p.Text)
		for _, s := range p.Steps {
			r.addf("     %s", s)
		}
	}
	return r
}
