

class PortPatternDetector():

    def __init__(self):
        pass

    def detect(self, port_list):
        detections = []
        if len (port_list) > 15:
            detections.append(('port_scan', [], 0.75))
        elif len(port_list) == 1 and port_list[0]['count']> 100:
            detections.append(('brute_force', [port_list[0]['port']], 1.0))

        return detections
