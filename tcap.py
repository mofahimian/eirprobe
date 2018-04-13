class Tcap:

    def process(self, layer, packet):
        return {'id': str(layer.otid) + str(layer.invokeid), 'timestamp': packet.sniff_timestamp}
