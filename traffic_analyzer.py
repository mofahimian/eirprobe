import redis
import sys

class TrafficAnalyzer:

    def __init__(self, redis_host, redis_port, redis_password):
        self.analyzers = {}
        self.reports = {}
        self.redis = redis.Redis(redis_host, redis_port, 0, redis_password)

    def register(self, traffic_type, traffic_type_processor):
        self.analyzers[traffic_type] = traffic_type_processor
        self.reports[traffic_type] = {'min': 9999, 'avg': 0, 'max': 0, 'count': 0, 'sum': 0}

    def process(self, packet):
        for layer in packet.layers:
            try:
                result = self.analyzers[layer.layer_name].process(layer, packet)

                if self.redis.exists(result.id):
                    response_time = result.timestamp - self.redis.get(result.id)
                    self._make_report(layer.layer_name, response_time)
                else:
                    self.redis.set(result.id, result.timestamp)
            except:
                print "Unexpected error:", sys.exc_info()[0]
                pass

    def _make_report(self, traffic_type, response_time):
        self.reports[traffic_type]['count'] = self.reports[traffic_type]['count'] + 1
        self.reports[traffic_type]['sum'] = self.reports[traffic_type]['sum'] + response_time

        if self.reports[traffic_type]['min'] > response_time:
            self.reports[traffic_type]['min'] = response_time

        if self.reports[traffic_type]['max'] < response_time:
            self.reports[traffic_type]['max'] = response_time

    def final_report(self):
        for traffic_type in self.reports:
            self.reports[traffic_type]['avg'] = self.reports[traffic_type]['sum'] / self.reports[traffic_type]['count']

        return self.reports
