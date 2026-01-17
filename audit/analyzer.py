from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional

from audit.models import ListeningPort, Risk, Exposure
from audit.parser import parse_ports
from audit.rules import assess_risk
from utils.net import determine_exposure


@dataclass(slots=True)
class AnalyzeOptions:
    exposed_only: bool = False
    min_risk: Optional[Risk] = None
    sort_by_risk: bool = True

_RISK_ORDER = {
    Risk.UNKNOWN: 0,
    Risk.LOW: 1,
    Risk.MEDIUM: 2,
    Risk.HIGH: 3,
    Risk.CRITICAL: 4,
}

def analyze_port_output(output: str, options: Optional[AnalyzeOptions] = None) -> List[ListeningPort]:
    """
    analyze 'ss -ltnup' command output
    """
    options = options or AnalyzeOptions()

    ports = parse_ports(output)
    return analyze_ports(ports, options=options)

def analyze_ports(ports: Iterable[ListeningPort], options: Optional[AnalyzeOptions]= None) -> List[ListeningPort]:
    options = options or AnalyzeOptions()

    analyzed: List[ListeningPort] = []

    for port in ports:
        #exposure class
        port.exposure = determine_exposure(port.address.ip)

        #risk assessment
        assess_risk(port)

        analyzed.append(port)

    #filter
    if options.exposed_only:
        analyzed = [p for p in analyzed if p.is_exposed()]

    if options.min_risk is not None:
        min_rank = _RISK_ORDER.get(options.min_risk, 0)
        analyzed = [p for p in analyzed if _RISK_ORDER.get(p.risk, 0) >= min_rank]

    #sort
    if options.sort_by_risk:
        analyzed.sort(key=lambda p: (-_RISK_ORDER.get(p.risk, 0), p.address.port, p.address.ip))
    
    return analyzed


def critical_ports(ports: Iterable[ListeningPort]) -> bool:
    """
    helper for CLI
    """
    return any(p.risk == Risk.CRITICAL for p in ports)
    