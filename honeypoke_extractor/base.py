import requests
import os
from urllib.parse import urlparse
import time

import logging

logger = logging.getLogger(__name__)

class FileCachingItem():

    def __init__(self, cache_dir, cache_time=(24*60*60), grab_wait=0.2):
        self._cache_dir = cache_dir
        if not os.path.exists(self._cache_dir):
            logger.debug("Creating %s", self._cache_dir)
            os.mkdir(self._cache_dir)
        self._cache_time = cache_time
        self._grab_wait = grab_wait


    def get_url(self, url, read_file=False):
        time.sleep(self._grab_wait)

        cache_path = os.path.join(self._cache_dir, os.path.basename(urlparse(url).path))
        if not os.path.exists(cache_path) or os.path.getmtime(cache_path) < (time.time()-self._cache_time):
            logger.debug("Downloading %s to %s", url, cache_path)

            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36'}

            resp = requests.get(url, headers=headers)
            cache_file = open(cache_path, "wb")
            cache_file.write(resp.content)
            cache_file.close()

        if read_file:
            cache_file = open(cache_path, "r")
            return_data = cache_file.read()
            cache_file.close()

            return return_data
        else:
            return None