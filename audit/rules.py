from __future__ import annotations

from typing import Callable, Iterable

from audit.models import ListeningPort, Risk, Exposure

Rule = Callable[[ListeningPort], bool]


def assess_risk(port: ListeningPort) -> None:
    """
    apply risk rules
    """
    for rule in RULES:
        if rule(port):
            return
    
    port.risk = Risk.UNKNOWN
    port.reason = "No matching risk rule found"


def rule_public(port: ListeningPort) -> bool:
    if (
        port.exposure == Exposure.PUBLIC and port.address.port in SENSESITIVE_PORTS
    ):
        port.risk = Risk.CRITICAL
        port.reason = f"Publicly exposed sensitive port {port.address.port}"
        return True
    return False

def rule_public_unknown(port: ListeningPort) -> bool:
    if port.exposure == Exposure.PUBLIC:
        port.risk = Risk.HIGH
        port.reason = "Service exposed to the public internet"
        return True
    return False

def rule_lan(port: ListeningPort) -> bool:
    if (
        port.exposure == Exposure.LAN and port.address.port in SENSESITIVE_PORTS
    ):
        port.risk = Risk.HIGH
        port.reason = f"LAN exposed sensitive port {port.address.port}"
        return True
    return False

def rule_lan_generic(port: ListeningPort) -> bool:
    if port.exposure == Exposure.LAN:
        port.risk = Risk.MEDIUM
        port.reason = "Service exposed to LAN"
        return True
    return False

def rule_local(port: ListeningPort) -> bool:
    if port.exposure == Exposure.LOCAL_ONLY:
        port.risk = Risk.LOW
        port.reason = "Service bound to localhost only"
        return True
    return False

SENSESITIVE_PORTS = {
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    67,68, # DHCP
    80,    # HTTP
    110,   # POP3
    143,   # IMAP
    161,   # SNMP
    443,   # HTTPS
    3306,  # MySQL
    5432,  # PostgreSQL
    6379,  # Redis
    9200,  # Elasticsearch
    27017, # MongoDB
}

RULES: Iterable[Rule] = [
    rule_public,
    rule_lan,
    rule_lan_generic,
    rule_local,
    rule_public_unknown
]