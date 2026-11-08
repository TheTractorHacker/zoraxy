package main

import "flag"

/*
	flags_certs.go

	Start-up flags of the certificate / ACME / offline feature set. They live in their own file
	to keep def.go untouched.
*/
var (
	offlineMode = flag.Bool("offline", false, "Offline mode: never make start-up/background outbound calls (GeoIP database download, public IP lookup, update checks, plugin store sync, webhooks). Explicit ACME requests still work. See DEVELOPMENT.md")

	allowHookCommands = flag.Bool("allow_hook_commands", false, "Allow the certificate event command hook to execute a program (arbitrary command execution by an administrator; off by default)")
	certsMapDir       = flag.String("certs_dir", "", "Watch this directory for certificates (certbot style: fullchain.pem/privkey.pem, *.crt/*.key, live/<name>/) and import them automatically; empty = off")
	certsMapInterval  = flag.Int("certs_dir_interval", 60, "Seconds between scans of -certs_dir")
)
