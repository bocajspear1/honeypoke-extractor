from .base import ContentDetectionProvider

import re
import base64
from urllib.parse import unquote


class PatternFindDetector(ContentDetectionProvider):
    def __init__(self):
        self._matched_items = []
        self._commands = set()

    def on_item(self, item):
        if item['input'].strip() == "":
            return

        inputs = []
        inputs.append(item['input'])
        inputs.append(unquote(item['input']))

        values = []

        for input_val in inputs:
            values = self.on_input(input_val)

        if len(values) > 0:
            item['found'] = values
            self._commands = self._commands.union(set(values))
            self._matched_items.append(item)

    def get_results(self):
        return { 
            "items": self._matched_items,
            "commands": list(self._commands)
        }

class PHPCommandDetector(PatternFindDetector):

    def on_input(self, input_val):
        if "<?" in input_val and "?>" in input_val and "<?xml" not in input_val:
            return re.findall(r"<\?.*\?>", input_val)  
        return [] 
    
class EncodedCommandDetector(PatternFindDetector):

    def on_input(self, input_val):
        return_list = []
        if "base64" in input_val:
            encoded_commands = re.findall(r"([a-zA-Z0-9+/=]+)[\"' ]*\|[ ]*base64", input_val)

            for encoded in encoded_commands:
                decoded = base64.b64decode(encoded)
                return_list.append(decoded.decode())

        return return_list


class DownloadDetector(PatternFindDetector):

    def on_input(self, input_val):
        command_list = []

        if "wget" in input_val:
            wget_list = re.findall(r"wget[ +]+http[s]{0,1}://[^ ;|\t+]+", input_val)

            for i in range(len(wget_list)):
                if "+" in wget_list[i]:
                    wget_list[i] = wget_list[i].replace("+", " ")

            command_list += wget_list

        if "curl" in input_val:
            curl_list =  re.findall(r"curl[ +]+http[s]{0,1}://[^ ;|\t+]+", input_val)

            for i in range(len(curl_list)):
                if "+" in curl_list[i]:
                    curl_list[i] = curl_list[i].replace("+", " ")

            command_list += curl_list

        return command_list
