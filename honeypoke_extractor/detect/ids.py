from .base import ContentDetectionProvider

import os
import re
import ast
import tarfile

import suricataparser
import regex


import logging

logger = logging.getLogger(__name__)

from honeypoke_extractor.base import FileCachingItem


class SnortRule():
    
    def __init__(self, rule_data):

        self._message = None
        self._port = None
        self._protocol = None
        self._str_matches = []
        self._regex_matches = []
        matched_values = []
        does_match = False
        self._inbound = True

        self._parse_rule(rule_data)

    def _parse_rule(self, rule_data):

        header_split_1 = rule_data.header.split("->")
        source_split = header_split_1[0].strip().split(" ")
        dest_split = header_split_1[1].strip().split(" ")

        self._protocol = source_split[0].lower()

        if dest_split[1].isnumeric():
            self._port = int(dest_split[1])

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
                    "do_match": do_match
                })
            elif option.name == "msg":
                self._message = option.value[1:-1]
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
                # print(option.value, re_value)
                self._regex_matches.append({
                    "value": regex.compile(re_value, flags=regex.POSIX)
                })
            else:
                # print(option)
                pass

    def matches_data(self, protocol, port, data):

        does_match = True
        matched_values = []

        # Check protocols are the same
        if protocol != self._protocol:
            return False, []
        
        if self._port is not None and port != self._port:
            return False, []
        
        for str_match in self._str_matches:
            if str_match['value'] in data:
                if str_match['do_match']:
                    does_match = does_match and True
                    matched_values.append(str_match['value'])
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
    def port(self):
        return self._port
    
    @property
    def inbound(self):
        return self._inbound
    

    def __str__(self):
        return f"{self._protocol}/{self._port} -> {self._message} {self._str_matches} AND {self._regex_matches}"

class SnortRuleDetector(ContentDetectionProvider, FileCachingItem):

    def __init__(self, source_urls=None, cache_dir=None):
        FileCachingItem.__init__(self, cache_dir, grab_wait=1)

        self._parsed_rules = []

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
                
        return matched

    def get_results(self):
        return {
            "rules": self._matched_rules,
            "items": self._matched_items
        }


class EmergingThreatRules(SnortRuleDetector):

    def __init__(self):
        SnortRuleDetector.__init__(self, cache_dir="/tmp/et-snortrules", source_urls=[
            'https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-web_server.rules'
            'https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-web_specific_apps.rules'
            'https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-exploit.rules'
            'https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-sql.rules'
            'https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-worm.rules'
            'https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-scada.rules'
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
            print(filter_member)

            data = rules_tar.extractfile(member)
            with open(os.path.join(cache_dir, filter_member), "wb") as out:
                out.write(data.read()) 

        rules_tar.close()
