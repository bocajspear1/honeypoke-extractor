

class DetectionProvider():
    pass


class ContentDetectionProvider(DetectionProvider):

    @property
    def name(self):
        return self.__class__.__name__
    
    def on_item(self, item):
        raise NotImplementedError
    
    def get_results(self):
        raise NotImplementedError