

class DetectionProvider():
    pass


class ContentDetectionProvider(DetectionProvider):
    
    def on_item(self, item):
        raise NotImplementedError
    
    def get_results(self):
        raise NotImplementedError