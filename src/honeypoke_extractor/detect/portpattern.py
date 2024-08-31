from pprint import pprint
from datetime import datetime, timedelta

from honeypoke_extractor.base import ContentDetectionProvider

class PortPatternDetector():

    def __init__(self):
        pass

    def detect(self, port_list):
        detections = []
        if len (port_list) > 15:
            detections.append(('port_scan', [], 0.75))
        elif len(port_list) == 1 and port_list[0]['count']> 100:
            detections.append(('brute_force', [port_list[0]['port']], 1.0))

        return detections

class ScanPatternDetector(ContentDetectionProvider):

    def __init__(self, wide_scan=60, tall_scan=6, brute_force=30, recalculate=False):
        self._wide_scan = wide_scan
        self._tall_scan = tall_scan
        self._brute_force = brute_force
        self._recalculate = recalculate

        self._ip_map = {}
        
    def on_item(self, item):
        source_ip = item['remote_ip']
        if source_ip not in self._ip_map:
            self._ip_map[source_ip] = {}
        
        port_str_id = f"{item['protocol']}/{item['port']}"

        if port_str_id not in self._ip_map[source_ip]:
            self._ip_map[source_ip][port_str_id] = []

        self._ip_map[source_ip][port_str_id].append(item)


    def _calculate(self):
        results = {
            'wide_scans': [],
            'brute_forces': [],
            'tall_scans': []
        }

        for source_ip in self._ip_map:
            if len(self._ip_map[source_ip].keys()) > self._tall_scan:
                results['tall_scans'].append((source_ip, list(self._ip_map[source_ip].keys())))
            for port_str_id in self._ip_map[source_ip]:
                seen_hosts = {} 
                for item in self._ip_map[source_ip][port_str_id]:
                    if item['host'] not in seen_hosts:
                        seen_hosts[item['host']] = []
                    seen_hosts[item['host']].append(item)
                # Check for wide scans (scans across the internet), meaning more than one host got it
                if len(seen_hosts.keys()) > 1:
                    already_found = False
                    for host in seen_hosts:
                        for host_item in seen_hosts[host]:
                            my_time = datetime.fromisoformat(host_item['time'])      
                            for other_host in seen_hosts:
                                if other_host == host:
                                    continue
                                for other_host_item in seen_hosts[other_host]:
                                    other_time = datetime.fromisoformat(other_host_item['time'])
                                    time_diff = None
                                    if other_time >= my_time:
                                        time_diff = other_time - my_time
                                    else:
                                        time_diff = my_time - other_time
                                    if time_diff <= timedelta(seconds=self._wide_scan) and not already_found:
                                        already_found = True

                                        results['wide_scans'].append((source_ip, port_str_id, list(seen_hosts.keys())))
                for seen_host in seen_hosts:
                    if len(seen_hosts[seen_host]) > self._brute_force:
                        results['brute_forces'].append((source_ip, port_str_id, seen_host, len(seen_hosts[seen_host])))
        return results
        
    def get_results(self):
        return self._calculate()
        