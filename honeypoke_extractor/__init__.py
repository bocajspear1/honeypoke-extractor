from datetime import datetime, timedelta
import socket

from elasticsearch import Elasticsearch

class HoneyPokeExtractor():

    def __init__(self, url, api_key=None, index="honeypoke"):
        self._client = Elasticsearch(url, api_key=api_key)
        self._index = index

    def _get_times(self, time_start, time_end):
        if time_start is None:
            delta = timedelta(hours=24)
            time_start = (datetime.now() - delta)
        
        if time_end is None:
            time_end = datetime.now()

        return time_start, time_end

    def _get_service(self, protocol, port):
        try:
            return socket.getservbyport(port, protocol)
        except OSError:
            return "?" 

    def get_top_ports(self, count=25, address=None, time_start=None, time_end=None):

        agg_name = "ports-agg"

        time_start, time_end = self._get_times(time_start, time_end)
        
        search_filter = {
            "bool": {
                "must": [],
                "filter": [{
                    "range": {
                        "time": {
                            "format": "strict_date_optional_time",
                            "gte": time_start,
                            "lte": time_end
                        }
                    }
                }],
                "should": [],
                "must_not": []
            }
        }

        if address is not None:
            search_filter['bool']['filter'].append(
                {
                    'term': {
                        "remote_ip": address
                    }
                }
            )

        results = self._client.search(index=self._index, aggs={
            agg_name: {
                "multi_terms": {
                    "terms": [{
                        "field": "port" 
                    }, {
                        "field": "protocol"
                    }],
                    "size": count
                }
            },
        }, query=search_filter
        ,size=0)

        result_list = []

        if len(results['aggregations'][agg_name]['buckets']) == 0:
            return result_list
        
        for bucket in results['aggregations'][agg_name]['buckets']:
            port = bucket['key'][0]
            protocol = bucket['key'][1]
            service = self._get_service(protocol, port)
            doc_count = bucket['doc_count']
            result_list.append({
                "port": port,
                "protocol": protocol,
                "service": service,
                "count": doc_count
            })
        
        return result_list

    def get_top_addresses(self, count=25, time_start=None, time_end=None):
        agg_name = "ips-agg"

        time_start, time_end = self._get_times(time_start, time_end)

        results = self._client.search(index="honeypoke", aggs={
            agg_name: {
                "terms": {
                    "field": "remote_ip",
                    "size": count
                }
            },
        }, query={"bool": {
        "must": [],
        "filter": [
            {
                "range": {
                    "time": {
                        "format": "strict_date_optional_time",
                        "gte": time_start,
                        "lte": time_end
                    }
                }
            }
        ],
        "should": [],
        "must_not": []
        }}
        ,size=0)

        ip_list = []
        for bucket in results['aggregations'][agg_name]['buckets']:
            ip_list.append({
                "address": bucket['key'],
                "count": bucket['doc_count']
            })

        return ip_list