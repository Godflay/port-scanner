# Port Audit Scanner

## What is it?
A simple Linux-only CLI tool that scans listening network ports and assesses their exposure and risk level.

Built as a small security-oriented utility to quickly answer:

“What services are listening on my machine, and which ones might be risky?”

## Features
Scans listening TCP/UDP ports using ss

Classifies exposure:

local (localhost only)

lan

public

Assigns a risk level:

low, medium, high, critical

Human-readable table output

JSON output for automation

Meaningful exit codes (CI / scripting friendly)

## Requirements
Linux

Python 3.10+

iproute2 (provides the ss command)

### On Fedora:
sudo dnf install iproute
or
sudo rpm-ostree install iproute

### On Debian/Ubuntu
sudo apt install iproute2

## Installation (dev/local)
git clone https://github.com/Godflay/port-scanner.git
cd port-scanner

python -m venv .venv
source .venv/bin/activate

python -m pip install -U pip setuptools wheel
python -m pip install -e .

## Usage
### run full scan
port-audit

### show only exposed services
port-audit --exposed-only

### filter by minimum risk level
port-audit --min-risk medium

### JSON output
port-audit --json

## Exit Codes
Code	Meaning
0	    No critical findings
2	    One or more critical findings
1	    Error during scan or analysis

## Example output
PROCESS        PID  PROTO  IP         PORT  EXPOSURE  RISK      REASON
sshd           812  tcp    0.0.0.0    22    public    critical  Publicly exposed sensitive port
cupsd          631  tcp    127.0.0.1  631   local     low       Service bound to localhost only


## General Notes
Parsing, classification, and risk rules are intentionally decoupled

Scanner logic is isolated from analysis logic

This is not a vulnerability scanner — it’s a visibility and risk-awareness tool.

## Limitations
Relies on ss output(format may vary slightly between distros)
Requires sufficient perms to see process information