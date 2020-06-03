import sys
import os
import pyshark
import json
import time
from datetime import datetime
from contextlib import suppress
import redis

r = redis.Redis(host="localhost", port=6379, db=0)

# value를 배열로 넣어 key가 중복일 시 추가
class Dictlist(dict):
    def __setitem__(self, key, value):
        try:
            self[key]
        except KeyError:
            super(Dictlist, self).__setitem__(key, [])
        self[key].append(value)


def dictSetter(dict, array):    # array ('key : value') each value  to dict
    for (idx, data) in enumerate(array):
        if idx == 1:
            if 'PDU' in data:
                dict["key"] = data
        else:
            if ": " in data:
                dt = data.split(": ")
                dict[dt[0]] = dt[1]

    return dict


def categorizing(pkt):
    print("############################################")
    # stamp = datetime.fromtimestamp(time.time()) # .strftime('%Y-%m-%d %H:%M:%S.%f') - default format
    stamp = datetime.utcnow().strftime('%y-%m-%d/%H:%M:%S.%f')[:]

    try:
        mainDict = Dictlist()
        ethDict = Dictlist()
        # print(pkt.transport_layer)
        # print(pkt.mms.unconfirmed_PDU_element)
        # print(pkt.mms.get_field_by_showname("AccessResult"))
        # print(pkt.mms.unconfirmed_PDU_element)
        # print(pkt["mms"].get_field_value(""))
        # print(pkt["mms"].get_field_value("unconfirmed_PDU_element"))
        # print([pt.rstrip() for pt in str(pkt).split("\r\n")])

        mainArray = str(pkt.mms).replace("\t", "").split("\r\n")

        ethArray = str(pkt.eth).replace("\t", "").split("\r\n")
        dictSetter(mainDict, mainArray)
        dictSetter(ethDict, ethArray)

        mainDict["eth"] = ethDict
        mainDict["timestamp"] = stamp

        print(mainDict)
        print(pkt)
        json_dict = json.dumps(mainDict, ensure_ascii=False,).encode("utf-8")
        r.set("packet-"+stamp,json_dict)

        try:
            pkt.ip
        except AttributeError as e:
            pass
            print(e)
        with suppress(AttributeError):
            print("ip: ", pkt.ip)


        # mms - negociatedParameterCBB : f100 하위 값
        #   1... .... = str1: True
        # 	.1.. .... = str2: True
    except AttributeError as e:
        print(e)

cap = pyshark .LiveCapture(interface='2', bpf_filter = 'tcp or udp') #  ether proto 0x88B8
# cap = pyshark.FileCapture('D:/dev/react-web-app/hmi_template/server/packet/mms/fresh.pcap', display_filter="mms or goose")
# , only_summaries=True ,  use_json=True, include_raw=True

cap.apply_on_packets(categorizing)

# for pkt in cap.sniff_continuously():    # LiveCapture only
#     print(pkt.tcp)
#     print("########################################################")
