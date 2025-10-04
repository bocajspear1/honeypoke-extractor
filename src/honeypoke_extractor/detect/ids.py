from honeypoke_extractor.base import ContentDetectionProvider

import os
import re
import ast
import tarfile

import suricataparser
import regex
import dpkt

import urllib.parse


import logging

logger = logging.getLogger(__name__)

from honeypoke_extractor.base import FileCachingItem


class SnortRule():
    
    def __init__(self, rule_data):

        self._message = None
        self._ports = None
        self._protocol = None
        self._offset = 0
        self._str_matches = []
        self._regex_matches = []
        matched_values = []
        does_match = False
        self._inbound = True

        self._parse_rule(rule_data)

    def var_replace(self, in_var):
        if in_var == "$HTTP_PORTS":
            return [80, 443]
        elif in_var == "$SSH_PORTS":
            return [22]
        elif ":" in in_var:
            # print(in_var)
            colon_split = in_var.split(":")

            start_int = 1
            if colon_split[0] != "":
                start_int = int(colon_split[0])
            end_int = 65535
            if colon_split[1] != "":
                end_int = int(colon_split[1])
            new_range = []
            while start_int <= end_int:
                new_range.append(start_int)
                start_int += 1
            return new_range
        return None

    def _parse_rule(self, rule_data):

        header_split_1 = rule_data.header.split("->")
        source_split = header_split_1[0].strip().split(" ")
        dest_split = header_split_1[1].strip().split(" ")

        self._protocol = source_split[0].lower()
        if self._protocol == "icmp":
            return

        port_list = []
        if dest_split[1].startswith("["):
            dest_port_list = dest_split[1][1:-1].split(",")
            for port_item in dest_port_list:
                new_val = self.var_replace(port_item)
                if new_val is not None:
                    port_list += new_val
                else:
                    port_list.append(int(port_item))
        elif dest_split[1].isnumeric():
            new_val = self.var_replace(dest_split[1])
            if new_val is not None:
                port_list += new_val
            else:
                port_list.append(int(dest_split[1]))
            
        
        if len(port_list) > 0:
            self._ports = port_list

        for option in rule_data.options:
            if option.name == "content":
                content_str = option.value
                matches = re.findall(r'\|(?:[0-9a-fA-F]{2}[ |])+', content_str)
                for match in matches:
                    hexified = "\\x" + match[1:-1].replace(" ", "\\x")
                    content_str = content_str.replace(match, hexified)
                

                do_match = True
                if content_str.startswith("!"):
                    content_str = content_str[1:]
                    do_match = False

                content_str = content_str.replace("\\:", ":")
                content_str = content_str.replace("\\;", ";")
                
                self._str_matches.append({
                    "value": ast.literal_eval(content_str),
                    "do_match": do_match,
                    "nocase": False
                })
            elif option.name == "depth":
                self._str_matches[-1]['depth'] = int(option.value)
            elif option.name == "offset":
                self._str_matches[-1]['offset'] = int(option.value)
            elif option.name == "distance":
                self._str_matches[-1]['distance'] = int(option.value)
            elif option.name == "within":
                self._str_matches[-1]['within'] = int(option.value)
            elif option.name.startswith("http_") :
                if 'sections' not in self._str_matches[-1]:
                    self._str_matches[-1]['sections'] = []
                self._str_matches[-1]['sections'].append(str(option.name))
                # print("hi", option.name, option.value)
            elif option.name == "msg":
                self._message = option.value[1:-1]
            elif option.name == "nocase":
                self._str_matches[-1]['nocase'] = True
            elif option.name == "flow":
                if "from_server" in option.value:
                    self._inbound = False
            elif option.name == "pcre":
                re_flags = 0
                re_value = option.value[1:-1]
                if re_value.startswith("/"):
                    re_value = re_value[1:]
                    while not re_value.endswith("/"):
                        if re_value[-1] == "i":
                            re_flags |= regex.IGNORECASE
                        re_value = re_value[:-1]
                    re_value = re_value[:-1]
                try:
                    self._regex_matches.append({
                        "value": regex.compile(re_value, flags=regex.POSIX)
                    })
                except regex._regex_core.error:
                    pass
            elif option.name in ("reference", "metadata", "rev", "sid", "classtype", "fast_pattern", 'threshold'):
                pass
            else:
                pass

    def matches_data(self, protocol, port, data):

        does_match = True
        matched_values = []

        # Check protocols are the same
        if protocol != self._protocol:
            return False, []
        
        if self._ports is not None and port not in self._ports:
            return False, []
        
        http_data = None
        http_invalid = False
        start_data = data
        last_find_offset = 0
        
        for str_match in self._str_matches:

            # For each str_match item, reset the data
            data = start_data

            
            if 'sections' in str_match:
                
                if str_match['sections'][0].startswith("http_"):
                    # Skip this str match entirely if HTTP parse failed since we match HTTP stuff
                    if http_invalid:
                        does_match = does_match and False
                        continue
                    try:
                        # We need to parse newlines
                        http_data = dpkt.http.Request(data.replace("\\r", "\r").replace("\\n", "\n").encode())
                    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                        http_invalid = True
                        does_match = does_match and False
                        continue
                    
                if http_data is not None:
                    if str_match['sections'][0] in ("http_client_body", "http_raw_body"):
                        data = http_data.body.decode()
                    elif str_match['sections'][0] == "http_uri":
                        data = http_data.uri
                    elif str_match['sections'][0] == "http_raw_uri":
                        data = data.split("\r\n")[0].split(" ")[1]
                    elif str_match['sections'][0] == "http_cookie":
                        if 'cookie' in http_data.headers:
                            data = http_data.headers['cookie']
                    elif str_match['sections'][0] == "http_raw_cookie":
                        if 'cookie' in http_data.headers:
                            data = urllib.parse.quote_plus(http_data.headers['cookie'])
                    elif str_match['sections'][0] == "http_method":
                        data = http_data.method
                    elif str_match['sections'][0] == "http_header":
                        header_full = ""
                        for header in http_data.headers:
                            header_full += header + ": " + str(http_data.headers[header]).lower() + "\r\n"
                        data = header_full
                        str_match['value'] = str_match['value'].lower()
                    else:
                        pass
                        # print(str_match['sections'][0])
                    
            if str_match['nocase']:
                str_match['value'] = str_match['value'].lower()
                data = data.lower()

            

            start = 0
            end = len(data)
            if 'distance' in str_match:
                start = last_find_offset + str_match['distance']
            if 'within' in str_match:
                end = last_find_offset + str_match['within']
            if 'offset' in str_match:
                start = str_match['offset']
            if 'depth' in str_match:
                end = start + str_match['depth']
            data = data[start:end]

            str_finding = data.find(str_match['value'])
            if str_finding != -1:
                if str_match['do_match']:
                    does_match = does_match and True
                    matched_values.append(str_match['value'])
                    last_find_offset = str_finding + len(str_match['value'])
                else:
                    does_match = does_match and False
            else:
                does_match = does_match and False

        for regex_match in self._regex_matches:
            search_result = regex_match['value'].search(data)
            if search_result is not None:
                does_match = does_match and True
                for group in search_result.groups():
                    matched_values.append(group)
            else:
                does_match = does_match and False

        if len(matched_values) == 0:
            does_match = False

        return does_match, matched_values


    @property
    def message(self):
        return self._message
    
    @property
    def protocol(self):
        return self._protocol
    
    @property
    def ports(self):
        return self._ports
    
    @property
    def inbound(self):
        return self._inbound
    

    def __str__(self):
        return f"{self._protocol}/{self._ports} -> {self._message} {self._str_matches} AND {self._regex_matches}"

class SnortRuleDetector(ContentDetectionProvider, FileCachingItem):

    def __init__(self, source_urls=None, cache_dir=None):
        FileCachingItem.__init__(self, cache_dir, grab_wait=1)

        self._parsed_rules = []

        logger.debug("Loading IDS rules")

        for source in source_urls:
            self.get_url(source)

        
        self._parse_rules()
        logger.debug("Loaded %d rules", len(self._parsed_rules))

        self._matched_rules = {}
        self._matched_items = []


    def _parse_rules(self):
        rules_dir_list = os.listdir(self._cache_dir)
        for dir_item in rules_dir_list:
            if dir_item.endswith(".rules"):
                rule_path = os.path.join(self._cache_dir, dir_item)
                raw_rules = suricataparser.parse_file(rule_path)
                for rule in raw_rules:
                    if not rule.enabled:
                        continue

                    new_rule = SnortRule(rule)

                    if not new_rule.inbound:
                        continue

                    self._parsed_rules.append(new_rule)

    def on_item(self, item):
        if item['input'].strip() == "":
            return

        port_str_id = f"{item['protocol']}/{item['port']}"

        matched = False
    
        for rule in self._parsed_rules:
            matches, matched_values = rule.matches_data(item['protocol'], item['port'], item['input'])
            if matches:
                if rule.message not in self._matched_rules:
                    self._matched_rules[rule.message] = 0
                self._matched_rules[rule.message] += 1

                if 'matched_rules' not in item:
                    item['matched_rules'] = []
                item['matched_rules'].append((rule.message, matched_values))

                self._matched_items.append(item)
                matched = True
        
        if matched == True:
            return item
        else:
            return None

    def get_results(self):
        return {
            "rules": self._matched_rules,
            "items": self._matched_items
        }


class EmergingThreatRules(SnortRuleDetector):

    def __init__(self):
        SnortRuleDetector.__init__(self, cache_dir="/tmp/et-snortrules", source_urls=[
            'https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-web_server.rules',
            'https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-web_specific_apps.rules',
            'https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-exploit.rules',
            'https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-sql.rules',
            'https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-worm.rules',
            'https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-scada.rules',
            'https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-scan.rules'
        ])

class SnortOrgRules(SnortRuleDetector):
    def __init__(self):
        cache_dir = "/tmp/snortorg-snortrules"
        SnortRuleDetector.__init__(self, cache_dir=cache_dir, source_urls=[
            'https://www.snort.org/downloads/community/community-rules.tar.gz'
        ])
        rules_tar = tarfile.open(os.path.join(cache_dir, 'community-rules.tar.gz'), "r")
        for member in rules_tar.getmembers():
            if not member.isfile():
                continue
            filter_member = member.name.replace("..", "").replace("/", "").replace("\\", "")

            data = rules_tar.extractfile(member)
            with open(os.path.join(cache_dir, filter_member), "wb") as out:
                out.write(data.read()) 

        rules_tar.close()
