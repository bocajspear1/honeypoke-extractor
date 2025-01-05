import json
import os

import pytest

from honeypoke_extractor.detect.ids import EmergingThreatRules

def test_ids_http_nomatch():
    test_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(test_dir, "nomatch.json"), "r") as input_file:
        items = json.load(input_file)
        testme = EmergingThreatRules()
        for item in items:
            print(item)
            assert testme.on_item(item) is None

def test_ids_http_matches():
    test_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(test_dir, "matches.json"), "r") as input_file:
        items = json.load(input_file)
        testme = EmergingThreatRules()
        for item in items:
            print(item)
            result = testme.on_item(item)
            print(result)
            assert not result is None
            assert len(result['matched_rules']) == 1
            assert result['matched_rules'][0][0] == "ET WEB_SPECIFIC_APPS Apache CloudStack SAML Authentication Bypass (CVE-2024-41107)"
            