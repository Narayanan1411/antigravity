from pathlib import Path

# Optional: local MaxMind DB
_HAS_GEO = False
try:
    import geoip2.database
    ROOT = Path(__file__).parent.parent
    _CITY_DB = geoip2.database.Reader(str(ROOT / "network" / "geoip" / "GeoLite2-City.mmdb"))
    _ASN_DB  = geoip2.database.Reader(str(ROOT / "network" / "geoip" / "GeoLite2-ASN.mmdb"))
    _HAS_GEO = True
except Exception:
    pass

def geo_lookup(ip: str) -> dict:
    """Return country and ASN for an IP."""
    if not _HAS_GEO or not ip or ip in ("127.0.0.1", "0.0.0.0", "unknown"):
        return {"country": None, "asn": None}
    
    country = None
    asn = None
    
    try:
        city = _CITY_DB.city(ip)
        country = city.country.name
    except Exception:
        pass
        
    try:
        asn_record = _ASN_DB.asn(ip)
        asn = str(asn_record.autonomous_system_organization)
    except Exception:
        pass
        
    return {"country": country, "asn": asn}
