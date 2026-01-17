from __future__ import annotations

import re
from typing import Iterable, List, Optional

from audit.models import (
    ListeningPort, 
    ProcessInfo,  
    SocketAddress,
    Protocol)

#regex patterns
_process_re = re.compile(
    r'users:\(\("(?P<name>[^"]+)",pid=(?P<pid>\d+)'
)

_ipv6_re = re.compile(r'^\[(?P<ip>.+)]:(?P<port>\d+)$')
_ipv4_re = re.compile(r'^(?P<ip>[^:]+):(?P<port>\d+)$')


def parse_ports(output: str) -> List[ListeningPort]:
    """
    parse 'ss -ltnup' command output
    """
    lines = output.strip().splitlines()

    if lines and lines[0].startswith("Netid"):
        lines = lines[1:]
    
    ports: List[ListeningPort] = []

    for line in lines:
        port = _parse_lines(line)
        if port:
            ports.append(port)

    return ports

def _parse_lines(line: str) -> Optional[ListeningPort]:
    
    parts = line.split()
    if len(parts) < 5:
        return None
    
    protocol = _parse_protocol(parts[0])
    address = _parse_address(parts)
    process = _parse_process(line)

    if not protocol or not address:
        return None
    
    return ListeningPort(
        protocol=protocol,
        address=address,
        process=process
    )

def _parse_protocol(token: str) -> Optional[Protocol]:
    token = token.lower()
    if token.startswith("tcp"):
        return Protocol.TCP
    
    if token.startswith("udp"):
        return Protocol.UDP
    return None

def _parse_address(parts: list[str]) -> Optional[SocketAddress]:
    
    for part in parts:
        if ":" not in part:
            continue

        addr = _parse_address_token(part)
        if addr:
            return addr
        
    return None

def _parse_address_token(token: str) -> Optional[SocketAddress]:
    """
    parses: 0.0.0.0:22
    127.0.0.1:6379
    [::]:443
    """
    
    match = _ipv6_re.match(token)
    
    if match:
        return SocketAddress(
            ip=match.group("ip"),
            port=int(match.group("port"))
        )
    
    match = _ipv4_re.match(token)

    if match:
        return SocketAddress(
            ip=match.group("ip"),
            port=int(match.group("port"))
        )
    
    return None

def _parse_process(line: str) -> Optional[ProcessInfo]:
    match = _process_re.search(line)
    if not match:
        return None
    
    return ProcessInfo(
        pid=int(match.group("pid")),
        name=match.group("name")
    )