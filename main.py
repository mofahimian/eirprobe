import pyshark
import configparser

from traffic_analyzer import TrafficAnalyzer
from diameter import Diameter
from tcap import Tcap


config = configparser.ConfigParser()
config.read('application.cfg')

redis_host = config.get('redis', 'host', fallback='127.0.0.1')
redis_port = config.get('redis', 'port', fallback='6379')
redis_password = config.get('redis', 'password', fallback='')

input_file = config.get('analyzer', 'input_file')

traffic_analyzer = TrafficAnalyzer(redis_host, redis_port, redis_password)
cap = pyshark.FileCapture(input_file=input_file, display_filter='diameter or gsm_map')

tcap = Tcap()
diameter = Diameter()
traffic_analyzer.register("diameter", diameter.process)
traffic_analyzer.register("tcap", tcap.process)

cap.apply_on_packets(callback=traffic_analyzer.process)
print(traffic_analyzer.reports)
