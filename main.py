import pyshark
import redis

# cap = pyshark.LiveCapture(interface='ens33')
cap = pyshark.FileCapture(input_file='eir1_20180314.pcap', display_filter='diameter or gsm_map')

red = redis.Redis()

pkt_counter = 0
min_res_time = 2
max_res_time = 0
sum_res_time = 0
interval = 1000


def process_packet(pkt):
    global pkt_counter, min_res_time, max_res_time, sum_res_time
    print("=========================================")

    for layer in pkt.layers:
        ckpt = False
        if layer.layer_name == 'diameter':
            try:
                if int(layer.flags_request) == 1:

                    red.set(name=str(layer.hopbyhopid) + str(layer.endtoendid), value=pkt.sniff_timestamp)

                elif int(layer.flags_request) == 0:
                    name = str(layer.hopbyhopid) + str(layer.endtoendid)
                    res_time = float(pkt.sniff_timestamp) - float(red.get(name))
                    print(str(min_res_time) + "," + str(sum_res_time / interval) + "," + str(max_res_time))

                    red.delete(name)
                    pkt_counter = pkt_counter + 1
                    sum_res_time = sum_res_time + res_time
                    if res_time > max_res_time:
                        max_res_time = res_time
                    if res_time < min_res_time:
                        min_res_time = res_time
                    if pkt_counter % interval == 0:
                        print(str(min_res_time) + "," + str(sum_res_time / interval) + "," + str(max_res_time))
                        min_res_time = 2
                        max_res_time = 0
                        sum_res_time = 0
            except (TypeError, AttributeError):
                print("DIAMETER EXCEPTION")
                pass

        if layer.layer_name == 'tcap':
            try:
                red.set(name=str(layer.otid) + str(layer.invokeid), value=pkt.sniff_timestamp)

            except (TypeError, AttributeError):
                pass
                print("M3UA REQ EXCEPTION")
                ckpt = True

            try:

                name = str(layer.dtid) + str(layer.invokeid)

                res_time = float(pkt.sniff_timestamp) - float(red.get(name))
                print(str(min_res_time) + "," + str(sum_res_time / interval) + "," + str(max_res_time))

                red.delete(name)
                pkt_counter = pkt_counter + 1
                sum_res_time = sum_res_time + res_time
                if res_time > max_res_time:
                    max_res_time = res_time
                if res_time < min_res_time:
                    min_res_time = res_time
                if pkt_counter % interval == 0:
                    print(str(min_res_time) + "," + str(sum_res_time / interval) + "," + str(max_res_time))
                    min_res_time = 2
                    max_res_time = 0
                    sum_res_time = 0
            except (TypeError, AttributeError):
                pass
                if ckpt:
                    pass
                    print(str(layer.dtid) + str(layer.invokeid))
                # print("M3UA RES EXCEPTION")


cap.apply_on_packets(callback=process_packet)
