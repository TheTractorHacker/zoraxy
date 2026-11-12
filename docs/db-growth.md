# What is in sys.db, what can make it grow, and how to compact it

This page is a code reading, not a measurement: it was written from the source (the tables below are every table the code creates or writes) and not from a live database. Nothing here changes a retention or a cap. Where a row says "none", the code has none today.

## See what uses it

**System > Settings > Database** (admin only, read only) lists the file size on disk, the free space inside the file and, per table, the key count and the stored bytes, biggest first, with one line on what each table holds. The same data is `GET /api/system/dbusage` (admin session only, not part of the `/api/v1` token API). It reads in one read transaction and stops after 5 seconds with a "truncated" mark, so a huge table cannot hold the database for long.

## Why the file can be far bigger than its data

BoltDB (the default backend) never gives pages back to the file system. Deleted or rewritten data only leaves free pages inside the file, which are reused for new data. So the file size is the high-water mark of everything that was ever stored at once, plus copy-on-write copies of the values being rewritten. In the card, "Free space inside" is what compaction can give back; "Data inside" is what really is stored.

## Growth table

"Day record" means one key per calendar day. Sizes are what the code allows, not what a given server has.

| Table | What is stored | Growth driver | Existing cap or retention | Recommendation |
| --- | --- | --- | --- | --- |
| `stats` | One JSON record per day (key `YYYY_MM_DD`): totals and counters per client IP, URL, user agent, referer, origin country, status code, method, downstream and upstream host, plus the same per site (up to 128 sites, then folded into `_other`). Rewritten in full every 10 minutes (`STATISTIC_AUTO_SAVE_INTERVAL`) and at the day change. | Distinct values per day (client IPs, URLs, user agents, referers: bots and scanners make these high) times the number of days kept. Every 10 minute rewrite of a multi-MB value also leaves copies behind that raise the file high-water mark. | Per day and dimension: soft cap `-stats_max_entries`, default 20000 (the lowest 10% by count are dropped when it is exceeded); per site and dimension a quarter of an eighth of it, minimum 100 (default 2500); 0 means unbounded (site maps then 1000). **No retention across days: old day records are never deleted.** | This is the only table that grows with time and traffic, so it is the first suspect for a very large file. Options: lower `-stats_max_entries`; a day-based retention (for example keep 90 to 400 days) is a feature that does not exist yet, to be decided by the admin; compact after removing data. Do not change the cap silently: it changes what the dashboards can show. |
| `settings` | Small values: listeners, TLS options, proxy timeouts, UI language, default error pages, CAPTCHA defaults. | Only when an admin changes a setting. | Fixed set of keys. | None. |
| `auth` | Admin accounts: password hashes, e-mail, role, disabled flag, session version, session key. | One set of keys per account. | Bounded by the number of accounts. | None. |
| `notifyknownip` | Known sign-in addresses per admin account (key `ips/<user>`) and the last update tag. | New addresses per account. | 20 addresses per account (`maxKnownIPs`), oldest dropped. | None. |
| `oauth2_sessions` | Server side sessions of the OAuth2 sign-in. | One key per sign-in. | At most 5000 (`maxPersistedSessions`, earliest expiry dropped first), expired records are removed. | None. |
| `zorxauth_browser_sessions`, `zorxauth_gateway_sessions` | Sessions of the Zoraxy authentication gateway. Written from memory when Zoraxy shuts down. | One key per live session at shutdown. | Expired ones are removed when Zoraxy starts and when the gateway settings are cleared; no limit on the count of live ones. | Low risk. |
| `posture` | Security overview: the baseline and a journal of the fixes that were applied (so they can be undone). | One entry per applied fix, appended to a per action list. | None found in the code. | Low risk: it only grows by manual clicks. |
| `apitokens`, `ruletemplates`, `plugins`, `plugin_hooks`, `wolmac`, `fwdproxy`, `webserv`, `acme`, `acmepref`, `redirect`, `statsettings`, `uptime`, `visitors`, `blocklog`, `dashboard`, `geodb`, `oauth2`, `oauth2_providers`, `auth_sso_forward`, `zorxauth`, `zorxauth_users`, `authelia`, `authentik` | Settings, one record per configured object (token, template, plugin, certificate, user, provider) or a few fixed keys (`dashboard` holds one daily bandwidth counter). | Only what an admin configures. | None needed, bounded by configuration. | None. |

## What does NOT grow sys.db

These were checked because they look like they could, and they keep their data elsewhere or in memory:

* **Blocked request log**: `conf/blocked.json.gz`, capped at 2000 entries (the `blocklog` table only holds its settings).
* **Visitors, uptime history, metrics, realtime statistics**: in memory; the `visitors` and `uptime` tables only hold their settings. They do not use the database module.
* **Audit and access logs** (auth audit, WAF audit, per site logs, system log): files, not sys.db.
* **Configuration history**: files in the history store, not sys.db.

## Compacting the database (offline)

Compaction copies every table into a fresh file and drops the free pages. It needs Zoraxy **stopped**: the compactor opens the database with the same fail-fast lock as startup and refuses to run (after waiting 10 seconds) when another process has it.

```bash
sudo systemctl stop zoraxy
./zoraxy -compact-db -dbpath /path/to/sys.db
sudo systemctl start zoraxy
```

Use the path the running instance uses (the Database card shows it), the service name of your installation and the same user as the service, or fix the owner afterwards (the compactor copies the owner of the old file when it is allowed to). What it does, in order, and stops at the first problem:

1. Opens the database (refuses when it is locked) and checks that the folder has room for the backup and the new file (twice the size of the database).
2. Writes a consistent backup next to it: `sys.db.bak-YYYYMMDD-HHMMSS`.
3. Compacts into `sys.db.compact-tmp`.
4. Checks the new file: it opens, passes BoltDB's consistency check, and every table has the same key count, nested table count and stored bytes as the old one.
5. Replaces `sys.db` with one atomic rename.

Until step 5 the original file is never modified, and a failure at any step removes the temporary file, so there is always a valid `sys.db`. It prints the size before and after. The backup is never deleted by Zoraxy; remove it yourself once the new file has been in use for a while. Compaction only applies to the BoltDB backend (LevelDB compacts itself).

If a second copy of Zoraxy ever hangs at start, it is a locked database: since this change it exits after 10 seconds with the path and the commands `sudo lsof <path>` and `ps -eo pid,etimes,args | grep [z]oraxy` to find the process that holds it.
