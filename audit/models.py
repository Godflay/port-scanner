from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


#Enums 
class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"

class Exposure(str, Enum):
    LOCAL_ONLY = "local"
    LAN = "lan"
    PUBLIC = "public"
    UNKNOWN = "unknown"

class Risk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


#core model
@dataclass(slots=True)
class ProcessInfo:
    """
    listening sockets information
    """
    pid: int
    name: str

@dataclass(slots=True)
class SocketAddress:
    """
    listen local adress
    """
    ip: str
    port: int

@dataclass(slots=True)
class ListeningPort:
    """
    listening to network ports
    """
    protocol: Protocol
    address: SocketAddress

    process: Optional[ProcessInfo] = None

    exposure: Exposure = Exposure.UNKNOWN
    risk: Risk = Risk.UNKNOWN
    reason: Optional[str] = None

def is_exposed(self) -> bool:
    return self.exposure in {Exposure.LAN, Exposure.PUBLIC}

def to_dict(self) -> dict:
    return {
        "protocol": self.protocol.value,
        "address": {
            "ip": self.address.ip,
            "port": self.address.port,
        },
        "process": {
            "pid": self.process.pid,
            "name": self.process.name,
        } if self.process else None,
        "exposure": self.exposure,
        "risk": self.risk,
        "reason": self.reason,
    }