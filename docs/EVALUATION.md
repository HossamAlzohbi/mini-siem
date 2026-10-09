# Evaluation

## Method

`minisiem simulate` writes three logs plus `truth.json`:

* **Benign traffic** (~13,500 events over 24 h): web visitors with a diurnal pattern, a health-check probe every minute,
  a legitimate crawler that causes a few 404s, users who mistype their password once to three times, search queries
  containing words such as `union` and `select`, normal Windows logons and processes, and occasional failed logons from
  internal addresses.
* **15 attack scenarios**, all inert text from documentation address ranges (`203.0.113.0/24`): fast and slow SSH brute
  force, SSH spraying, SSH compromise, a Nikto-style scan, sqlmap, manual SQL injection, path traversal, Log4Shell
  strings, XSS, web credential stuffing, Windows brute force and spraying, a full Windows intrusion chain and an Office
  macro launching encoded PowerShell.

`minisiem evaluate` checks every *(scenario, expected rule)* pair. A pair counts as detected when an alert from that rule
involves an attacker address (or, for address-less events such as "user created", the same host inside the scenario's
time window). An alert that involves no attack at all is a false positive; an alert from a different rule on attacker
traffic is reported as *extra*.

## Result (seed 7)

```
scenario                  expected rule                 detected  time to detect
ssh_bruteforce_fast       ssh_bruteforce                yes       10s
ssh_password_spray        ssh_password_spray            yes       360s
ssh_slow_bruteforce       ssh_slow_bruteforce           yes       3420s
ssh_compromise            ssh_bruteforce                yes       21s
ssh_compromise            ssh_compromise                yes       70s
ssh_compromise            ssh_root_login                yes       70s
web_scan_nikto            web_scanner_useragent         yes       0s
web_scan_nikto            web_404_flood                 yes       9s
web_scan_nikto            web_scanner_probing           yes       0s
web_sqlmap                web_sqli                      yes       0s
web_sqlmap                web_scanner_useragent         yes       0s
web_manual_sqli           web_sqli                      yes       0s
web_path_traversal        web_path_traversal            yes       0s
web_log4shell             web_log4shell                 yes       0s
web_xss                   web_xss                       yes       0s
web_credential_stuffing   web_login_bruteforce          yes       13s
win_bruteforce            win_bruteforce                yes       21s
win_password_spray        win_password_spray            yes       240s
win_intrusion_chain       win_bruteforce                yes       42s
win_intrusion_chain       win_compromise                yes       170s
win_intrusion_chain       win_encoded_powershell        yes       190s
win_intrusion_chain       win_credential_dumping_cli    yes       230s
win_intrusion_chain       win_user_created              yes       270s
win_intrusion_chain       win_admin_group_added         yes       280s
win_intrusion_chain       win_service_installed         yes       320s
win_intrusion_chain       win_log_cleared               yes       370s
win_office_macro          win_office_spawns_shell       yes       0s
win_office_macro          win_encoded_powershell        yes       0s
Detected 28/28 expected detections (100%)
Total alerts: 30  |  extra alerts on attacker traffic: 2  |  false positives: 0 (on ~13560 benign events)
  extra: ssh_password_spray (high) at 2026-10-05T02:14:00Z during ssh_bruteforce_fast
  extra: ssh_slow_bruteforce (medium) at 2026-10-05T02:14:00Z during ssh_bruteforce_fast
```

The two *extra* alerts are expected: a 120-attempt SSH brute force also satisfies the spraying and slow-brute-force
rules. Time to detect is measured from the scenario start to the moment the rule's threshold is crossed (for the
slow brute force that is 57 minutes by design: 20 failures at one per 3 minutes).

## Robustness

Seeds 1-30 give identical results: 28/28 expected detections, 0 false positives, and 0 alerts when the simulator is run
without attacks. Seeds change addresses, user names, timing jitter and benign volume, **not** the structure of the attacks,
so this shows the result is not a fluke of one random draw, not that it generalises.

## Why this is optimistic

* The author wrote both the rules and the test data. Rules that look for `union select` will of course find `union select`.
* Real internet-facing servers receive continuous background noise, legitimate traffic that resembles attacks, and
  log formats that differ from the clean ones simulated here.
* Thresholds were chosen for the simulated traffic.

What *is* checked: the engine's behaviour at threshold boundaries, window expiry, grouping, ordering, burst merging
and aliasing (`tests/test_engine.py`); each parser against hand-written lines (`tests/test_parsers.py`); and the attacks the
rules are known to miss (`tests/test_known_gaps.py`).

## How to get a real measurement

1. Ingest a week of your own logs and run `minisiem detect`. Every alert is either true, a false positive, or something to tune.
2. Record per-rule false-positive counts and adjust thresholds or add allow-lists.
3. Replay a known attack (for example your own authorised scanner run against a test server) and see whether it is caught.
