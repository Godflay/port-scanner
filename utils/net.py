from __future__ import annotations

import ipaddress

from audit.models import Exposure

def determine_exposure(ip: str) -> Exposure:
    """
    Determine the exposure level of a given IP address.
    """
    
    try:
        ip_address = ipaddress.ip_address(ip)
    
    except ValueError:
        return Exposure.UNKNOWN

    #handle loopback addresses
    if ip_address.is_loopback:
        return Exposure.LOCAL_ONLY
    
    #handle wildcard addresses
    if ip in ("0.0.0.0", "::"):
        return Exposure.PUBLIC
    
    #handle LAN
    if ip_address.is_private:
        return Exposure.LAN
    
    #public facing
    return Exposure.PUBLIC