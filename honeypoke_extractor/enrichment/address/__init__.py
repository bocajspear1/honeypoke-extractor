import requests


class EnrichmentProvider():
    pass

class AbuseIPDBEnrichment(EnrichmentProvider):
    '''Enrichment from AbuseIPDB service. Requires API key.
    
    Docs: https://docs.abuseipdb.com/
    '''

    def __init__(self, api_key):
        self._api_key = api_key

    def enrich(self, address):
        resp = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={address}&maxAgeInDays=90&verbose", headers={
            'Key': self._api_key,
            "Accept": "application/json"
        })
        
        return resp.json()['data']
    

class IPAPIEnrichment(EnrichmentProvider):
    '''Enrichment from IP-API service
    
    Docs: https://ip-api.com/docs
    '''
    def enrich(self, address):
        resp = requests.get(f"http://ip-api.com/json/{address}", headers={
            "Accept": "application/json"
        })
        
        return resp.json()
    
class ThreatFoxEnrichment(EnrichmentProvider):
    '''Enrichment from ThreatFox service
    
    Docs: https://threatfox.abuse.ch/api/
    '''
    def enrich(self, address):
        resp = requests.post(f"https://threatfox-api.abuse.ch/api/v1/", json={
            "query": "search_ioc", 
            "search_term": address
        },
        headers={
            "Accept": "application/json"
        })
        
        return resp.json()