from pprint import pprint
from datetime import datetime, timedelta

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

class ScanPatternDetector():

    def __init__(self):
        pass

    def detect(self, item_list):

        ip_map = {}
        for item in item_list:
            source_ip = item['remote_ip']
            if source_ip not in ip_map:
                ip_map[source_ip] = {}
            
            port_str_id = f"{item['protocol']}/{item['port']}"

            if port_str_id not in ip_map[source_ip]:
                ip_map[source_ip][port_str_id] = []

            ip_map[source_ip][port_str_id].append(item)

        results = {
            'wide_scans': [],
            'brute_forces': [],
            'tall_scans': []
        }
        
        for source_ip in ip_map:
            if len(ip_map[source_ip].keys()) > 5:
                results['tall_scans'].append((source_ip, list(ip_map[source_ip].keys())))
            for port_str_id in ip_map[source_ip]:
                seen_hosts = {} 
                for item in ip_map[source_ip][port_str_id]:
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
                                    if time_diff <= timedelta(minutes=1) and not already_found:
                                        already_found = True

                                        results['wide_scans'].append((source_ip, port_str_id, list(seen_hosts.keys())))
                for seen_host in seen_hosts:
                    if len(seen_hosts[seen_host]) > 20:
                        results['brute_forces'].append((source_ip, port_str_id, len(seen_hosts[seen_host])))

        return results