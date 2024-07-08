import requests
import ipaddress
import time

from honeypoke_extractor.base import FileCachingItem

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
    def enrich(self, addresses):

        if isinstance(addresses, str):
            addresses = [addresses]

        results_map = {}

        for address in addresses:
            if address in results_map:
                continue
            resp = requests.get(f"http://ip-api.com/json/{address}", headers={
                "Accept": "application/json"
            })
            results_map[address] = resp.json()
            time.sleep(0.4)

        return results_map
    
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

        data = resp.json()

        if data['query_status'] == 'no_result':
            return None
        
        return data

class FeodoTrackerEnrichment(EnrichmentProvider):
    '''Enrichment from Feodo Tracker, which tracks botnets
    
    Docs: https://feodotracker.abuse.ch/blocklist/
    '''

    def __init__(self):
        resp = requests.get(f"https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            headers={
                "Accept": "application/json"
            }
        )
        
        self._c2list = resp.json()

    def enrich(self, address):
        for item in self._c2list:
            if item['ip_address'] == address:
                return item
        return None

class BlockListEnrichment(EnrichmentProvider, FileCachingItem):
    '''Enrichment from a number of blocklists
    
    - https://www.binarydefense.com/banlist.txt (See the lists's comments for usage limitations)

    '''

    def __init__(self):

        FileCachingItem.__init__(self, "/tmp/iplists")
        self._banlist = self._get_list("https://iplists.firehol.org/files/bds_atif.ipset")
        self._firehol1 = self._get_list("https://iplists.firehol.org/files/firehol_level1.netset")
        self._firehol2 = self._get_list("https://iplists.firehol.org/files/firehol_level2.netset")
        self._firehol3 = self._get_list("https://iplists.firehol.org/files/firehol_level3.netset")
        
    def _get_list(self, url):
        
        iplist_data = self.get_url(url)
        return_list = []
        
        for line in iplist_data.split("\n"):
            if line.startswith("#") or line.strip() == "":
                continue
            if "/" in line:
                return_list.append(ipaddress.IPv4Network(line))
            else:
                return_list.append(ipaddress.IPv4Network(line + "/32"))
        return return_list

    def _in_list(self, banlist, address):
        for item in banlist:
            if ipaddress.IPv4Address(address) in item:
                return True
        return False

    def enrich(self, addresses):
        """Takes a single or array of IP addresses and enriches them
        
        """

        if isinstance(addresses, str):
            addresses = [addresses]

        results_map = {}

        for address in addresses:
            results_map[address] = {
                "binary_defense": self._in_list(self._banlist, address),
                "firehol_1": self._in_list(self._firehol1, address),
                "firehol_2": self._in_list(self._firehol2, address),
                "firehol_3": self._in_list(self._firehol3, address),
            }

        return results_map