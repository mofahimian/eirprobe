class Diameter:

    def process(self, layer, packet):
        return {'id': str(layer.hopbyhopid) + str(layer.endtoendid), 'timestamp': packet.sniff_timestamp}
