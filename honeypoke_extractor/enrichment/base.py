from honeypoke_extractor.base import HoneypokeProvider

class EnrichmentProvider(HoneypokeProvider):
    pass

class IPEnrichmentProvider(EnrichmentProvider):

    def on_ip(self, address):
        raise NotImplementedError
    
class PortEnrichmentProvider(EnrichmentProvider):

    def on_port(self, port):
        raise NotImplementedError