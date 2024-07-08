from .base import ContentDetectionProvider

import re
import base64
from urllib.parse import unquote

class CommandDetector(ContentDetectionProvider):

    def __init__(self):
        self._matched_items = []
        self._commands = set()

    def on_item(self, item):
        if item['input'].strip() == "":
            return
        
        command_list = []
        if "wget" in item['input']:
            command_list +=  re.findall(r"wget[ ]+http[s]{0,1}://[^ ;|\t]+", item['input'])
            
        if "curl" in item['input']:
            command_list +=  re.findall(r"curl[ ]+http[s]{0,1}://[^ ;|\t]+", item['input'])

        if "base64" in item['input']:
            encoded_commands = re.findall(r"([a-zA-Z0-9+/=]+)[\"' ]*\|[ ]*base64", item['input'])

            if len(encoded_commands) == 0:
                unquoted = unquote(item['input'])
                encoded_commands = re.findall(r"([a-zA-Z0-9+/=]+)[\"' ]*\|[ ]*base64", unquoted)

            
            for encoded in encoded_commands:
                decoded = base64.b64decode(encoded)
                command_list.append(decoded.decode())
        
        if len(command_list) > 0:
            item['commands'] = command_list
            self._commands = self._commands.union(set(command_list))
            self._matched_items.append(item)

            

    def get_results(self):
        return { 
            "items": self._matched_items,
            "commands": self._commands
        }