from datetime import timedelta, datetime
import socket

from datetime import timezone
UTC = timezone.utc

from pprint import pprint

from honeypoke_extractor.base import IPEnrichmentProvider, PortEnrichmentProvider

from elasticsearch import Elasticsearch

class HoneyPokeExtractor():

    def __init__(self, url, api_key=None, index="honeypoke"):
        self._client = Elasticsearch(url, api_key=api_key)
        self._index = index

    def _get_times(self, time_start, time_end):
        if time_start is None:
            delta = timedelta(hours=24)
            time_start = (datetime.now(UTC) - delta)
        
        if time_end is None:
            time_end = datetime.now(UTC)

        return time_start, time_end

    def _get_service(self, protocol, port):
        try:
            return socket.getservbyport(port, protocol)
        except OSError:
            return "?" 

    def get_top_ports(self, count=25, address=None, time_start=None, time_end=None, per_remote=False, enrich=None):

        if enrich is not None:
            for enrich_obj in enrich:
                if not isinstance(enrich_obj, PortEnrichmentProvider):
                    raise ValueError("Must be a PortEnrichmentProvider class")

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

        sub_aggs = {}
        if per_remote:
            sub_aggs = {
                "subagg": {
                    "terms": {
                        "field": "remote_ip",
                        "size": 100
                    }
                }
            } 

        results = self._client.search(index=self._index, aggs={
            agg_name: {
                "multi_terms": {
                    "terms": [{
                        "field": "port" 
                    }, {
                        "field": "protocol"
                    }],
                    "size": count
                },
                "aggs": sub_aggs
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

            new_item = {
                "port": port,
                "protocol": protocol,
                "service": service,
            }

            if per_remote:
                new_item['count'] = {}
                for sub_agg in bucket['subagg']['buckets']:
                    new_item['count'][sub_agg['key']] = sub_agg['doc_count']
            else:
                new_item['count'] = bucket['doc_count']

            

            if enrich is not None:
                for enrich_obj in enrich:
                    data = enrich_obj.on_port(new_item['protocol'], new_item['port'])
                    new_item[enrich_obj.name] = data

            result_list.append(new_item)
        
        return result_list

    def get_top_addresses(self, count=25, port=None, protocol=None, time_start=None, time_end=None, per_host=False, enrich=None):

        if enrich is not None:
            for enrich_obj in enrich:
                if not isinstance(enrich_obj, IPEnrichmentProvider):
                    raise ValueError("Must be a IPEnrichmentProvider class")

        agg_name = "ips-agg"

        time_start, time_end = self._get_times(time_start, time_end)

        search_filter = {
            "bool": {
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
            }
        }

        if port is not None and protocol is not None:
            search_filter['bool']['filter'].append(
                {
                    'term': {
                        "port": port,
                    }
                }
            )
            search_filter['bool']['filter'].append(
                {
                    'term': {
                        "protocol": protocol,
                    }
                }
            )

        sub_aggs = {}
        if per_host:
            sub_aggs = {
                "subagg": {
                    "terms": {
                        "field": "host"
                    }
                }
            } 

        results = self._client.search(index=self._index, aggs={
            agg_name: {
                "terms": {
                    "field": "remote_ip",
                    "size": count
                },
                "aggs": sub_aggs
            },
        }, query=search_filter
        ,size=0)

        ip_list = []
        for bucket in results['aggregations'][agg_name]['buckets']:
            new_item = {
                "address": bucket['key']
            }

            if per_host:
                new_item['count'] = {}

                for sub_agg in bucket['subagg']['buckets']:
                    new_item['count'][sub_agg['key']] = sub_agg['doc_count']
            else:
                new_item['count'] = bucket['doc_count']

            if enrich is not None:
                for enrich_obj in enrich:
                    data = enrich_obj.on_ip(new_item['address'])
                    new_item[enrich_obj.name] = data

            ip_list.append(new_item)

        return ip_list
    
    def get_hits(self, detectors=None, enrichments=None, bulk_ip_enrichments=None, count=100, time_start=None, time_end=None, 
                 contains=None, filter_ports=None, filter_remote_ips=None, return_matches=False):

        time_start, time_end = self._get_times(time_start, time_end)

        amount_left = count
        search_after = None
        return_list = []

        must = []
        if contains is not None:
            must.append({
                "terms": {
                    "input": contains,
                }
            })

        must_not = []

        # Filter out certain remote IP addresses
        if filter_remote_ips is not None:
            for remote_ip in filter_remote_ips:
                must_not.append({
                    "term": {
                        "remote_ip": remote_ip
                    }
                })

        # Filter out certain ports
        if filter_ports is not None:
            must_not_subfilter = {
                "bool": {
                    "filter": []
                }
            }
            for port in filter_ports:
                port_split = port.split("/")
                protocol = port_split[0]
                port_int = int(port_split[1])
                must_not_subfilter['bool']['filter'].append({
                    "term" : { 
                        "port": port_int
                    }
                })
                must_not_subfilter['bool']['filter'].append({
                    "term" : { 
                        "protocol" : protocol,
                    }
                })
                must_not.append(must_not_subfilter)
            
                
        while amount_left > 0: 

            limit = amount_left
            if limit > 10000:
                limit = 10000


            query = {"bool": {
                "must": must,
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
                "must_not": must_not
            }}

            

            if amount_left == count:
                results = self._client.search(index=self._index, query=query, sort= [
                    {"time": "desc"}
                ], size=limit)

                if len(results['hits']['hits']) == 0:
                    amount_left = 0
                else:
                    search_after = results['hits']['hits'][-1]['sort']
            else:
                results = self._client.search(index=self._index, query=query, sort= [
                    {"time": "desc"}
                ], size=limit, search_after=search_after)

                if len(results['hits']['hits']) == 0:
                    amount_left = 0
                else:
                    search_after = results['hits']['hits'][-1]['sort']

            amount_left -= limit

            for item in results['hits']['hits']:
                
                return_item = item['_source']
                return_item['_id'] = item['_id']

                do_enrich = False
                do_insert = True
                if detectors is not None:
                    for detector in detectors:
                        detector_results = detector.on_item(return_item)
                        if detector_results is not None:
                            do_enrich = True
                            return_item = detector_results
                        elif return_matches:
                            do_insert = False

                else:
                    do_enrich = True
                
                if enrichments is not None and do_enrich:
                    for enrichment in enrichments:
                        new_item = enrichment.on_item(return_item)
                        if new_item is not None:
                            return_item = new_item
                if do_insert:
                    return_list.append(return_item)


        if detectors is None:
            return return_list, None
        detector_results = {}
        for detector in detectors:
            detector_data = detector.get_results()
            detector_results[detector.name] = detector_data
        


        if bulk_ip_enrichments is not None:
            ip_list = []
            for item in return_list:
                if item['remote_ip'] not in ip_list:
                    ip_list.append(item['remote_ip'])
            for bulk_enrich in bulk_ip_enrichments:
                detector_results[bulk_enrich.name] = bulk_enrich.bulk(ip_list)


        return return_list, detector_results
