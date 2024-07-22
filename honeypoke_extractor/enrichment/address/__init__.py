import requests
import ipaddress
import time
import json

from honeypoke_extractor.base import FileCachingItem
from honeypoke_extractor.enrichment.base import IPEnrichmentProvider

class AbuseIPDBEnrichment(IPEnrichmentProvider):
    '''Enrichment from AbuseIPDB service. Requires API key.
    
    Docs: https://docs.abuseipdb.com/
    '''

    def __init__(self, api_key):
        self._api_key = api_key
        self._ip_map = {}

    def on_ip(self, address):
        if address not in self._ip_map:
            resp = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={address}&maxAgeInDays=90&verbose", headers={
            'Key': self._api_key,
                "Accept": "application/json"
            })
            
            self._ip_map[address] = resp.json()['data']
        return self._ip_map[address]

    def on_item(self, item):
        remote_ip = item['remote_ip']
        item['abuseip'] = self.on_ip(remote_ip)
        return item

    def get_results(self):
        return {
            "ip_addresses": self._ip_map
        }
         
class IPAPIEnrichment(IPEnrichmentProvider):
    '''Enrichment from IP-API service
    
    Docs: https://ip-api.com/docs
    '''

    def __init__(self):
        self._ip_map = {}

    def on_ip(self, address):
        if address not in self._ip_map:
            resp = requests.get(f"http://ip-api.com/json/{address}", headers={
                "Accept": "application/json"
            })
            self._ip_map[address] = resp.json()
            time.sleep(0.4)
        return self._ip_map[address]

    def on_item(self, item):
        remote_ip = item['remote_ip']
        item['ipapi'] = self.on_ip(remote_ip)
        return item


    def get_results(self):
        return {
            "ip_addresses": self._ip_map
        }
    
class ThreatFoxEnrichment(IPEnrichmentProvider):
    '''Enrichment from ThreatFox service
    
    Docs: https://threatfox.abuse.ch/api/
    '''

    def __init__(self):
        self._ip_map = {}


    def on_ip(self, address):
        if address not in self._ip_map:
            resp = requests.post(f"https://threatfox-api.abuse.ch/api/v1/", json={
                "query": "search_ioc", 
                "search_term": address
            },
            headers={
                "Accept": "application/json"
            })

            data = resp.json()

            if data['query_status'] != 'no_result':
                self._ip_map[address] = data['data']
            else:
                self._ip_map[address] = None
            time.sleep(0.4)
        return self._ip_map[address]

    def on_item(self, item):
        remote_ip = item['remote_ip']
        
        item['threatfox'] = self.on_ip(remote_ip)
        return item


    def get_results(self):
        return {
            "ip_addresses": self._ip_map
        }

class FeodoTrackerEnrichment(IPEnrichmentProvider, FileCachingItem):
    '''Enrichment from Feodo Tracker, which tracks botnets
    
    Docs: https://feodotracker.abuse.ch/blocklist/
    '''

    def __init__(self):
        FileCachingItem.__init__(self, "/tmp/feodo")
        block_list = self.get_url("https://feodotracker.abuse.ch/downloads/ipblocklist.json", headers={
            "Accept": "application/json"
        }, read_file=True)

        
        self._c2list = json.loads(block_list)
        self._ip_map = {}


    def on_ip(self, address):
        if address not in self._ip_map:
            self._ip_map[address] = False
            for c2_item in self._c2list:
                if c2_item['ip_address'] == address:
                    self._ip_map[address] = True
        return self._ip_map[address]
            

    def on_item(self, item):
        remote_ip = item['remote_ip']

        item['feodotracker'] = self.on_ip(remote_ip)
        return item


    def get_results(self):
        return {
            "ip_addresses": self._ip_map
        }

class BlockListEnrichment(IPEnrichmentProvider, FileCachingItem):
    '''Enrichment from a number of blocklists
    
    - https://www.binarydefense.com/banlist.txt (See the lists's comments for usage limitations)

    '''

    def __init__(self):

        FileCachingItem.__init__(self, "/tmp/iplists")
        self._banlist = self._get_list("https://iplists.firehol.org/files/bds_atif.ipset")
        self._firehol1 = self._get_list("https://iplists.firehol.org/files/firehol_level1.netset")
        self._firehol2 = self._get_list("https://iplists.firehol.org/files/firehol_level2.netset")
        self._firehol3 = self._get_list("https://iplists.firehol.org/files/firehol_level3.netset")

        self._ip_map = {}
        
    def _get_list(self, url):
        
        iplist_data = self.get_url(url, read_file=True)
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

    def on_ip(self, address):
        if address not in self._ip_map:
            self._ip_map[address] = {
                "binary_defense": self._in_list(self._banlist, address),
                "firehol_1": self._in_list(self._firehol1, address),
                "firehol_2": self._in_list(self._firehol2, address),
                "firehol_3": self._in_list(self._firehol3, address),
            }
        return self._ip_map[address]

    def on_item(self, item):
        remote_ip = item['remote_ip']

        item['blocklists'] = self.on_ip(remote_ip)
        return item


    def get_results(self):
        return {
            "ip_addresses": self._ip_map
        }

class OTXEnrichment(IPEnrichmentProvider):

    def __init__(self, api_key, url_list=False, passive_dns=True, general=True):
        self._api_key = api_key
        self._ip_map = {}
        self._url_list = url_list
        self._passive_dns = passive_dns
        self._general = general

    def _get_section(self, remote_ip, section):
        resp = requests.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{remote_ip}/{section}", headers={
            'X-OTX-API-KEY': self._api_key,
            "Accept": "application/json"
        })

        time.sleep(0.2)
        return resp.json()
    
    def on_ip(self, address):
        if address not in self._ip_map:

            insert_item = {}

            if self._general:
                resp_json = self._get_section(address, "general")
                insert_item['general'] = resp_json

            if self._passive_dns:
                resp_json = self._get_section(address, "passive_dns")
                insert_item['passive_dns'] = resp_json['passive_dns']
            
            if self._url_list:
                # Only returns max of 10
                resp_json = self._get_section(address, "url_list")
                insert_item['url_list'] = resp_json['url_list']
            
            self._ip_map[address] = insert_item
        return self._ip_map[address]

    def on_item(self, item):
        remote_ip = item['remote_ip']

        item['otx'] = self.on_ip(remote_ip)
        return item

    def get_results(self):
        return {
            "ip_addresses": self._ip_map
        }
    

class InternetDBEnrichment(IPEnrichmentProvider):
    '''Enrichment from InternetDB service
    
    Docs: https://internetdb.shodan.io/
    '''

    def __init__(self):
        self._ip_map = {}

    def on_ip(self, address):
        if address not in self._ip_map:
            resp = requests.get(f"https://internetdb.shodan.io/{address}", headers={
                "Accept": "application/json"
            })
            if resp.status_code == 404:
                self._ip_map[address] = None
            else:
                self._ip_map[address] = resp.json()
            # if 'details' in self._ip_map[remote_ip] and self._ip_map[remote_ip]['details'] == 
            time.sleep(0.2)
        return self._ip_map[address]

    def on_item(self, item):
        remote_ip = item['remote_ip']

        item['internetdb'] = self.on_ip(remote_ip)
        return item


    def get_results(self):
        return {
            "ip_addresses": self._ip_map
        }