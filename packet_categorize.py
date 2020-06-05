import time
import re
from datetime import datetime, timedelta
import pyshark
import redis
import json
from crontab import CronTab
from contextlib import suppress
from collections import deque
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from multiprocessing import Process


class Dictlist(dict):  # dictionary value 가 중복일 시 배열로 추가함
    def __setitem__(self, key, value):
        try:
            self[key]
        except KeyError:
            super(Dictlist, self).__setitem__(key, [])
        self[key].append(value)


class Report(dict):
    def __init__(self, redis_conn):
        self.r = redis_conn

    def __setitem__(self, key, value):
        try:
            self.__dict__[key]
            prev = self.__dict__[key]["timestamp"]
            curr = value["timestamp"]

            period = round(curr - prev, 6)

            # if period >= timedelta(seconds=5):
            if period >= 5.10:
                # RPT delayed: ViPAM5000PRT/LLN0$urcbA , 5.3140869140625
                print(value["vmd-specific"], "delayed:", key, ",", period)

                # r.lpush(key, period.total_seconds())  # lpush, lrange / array로 집어넣기
                # print(r.lrange([i.decode() for i in delayed_ied][0], 0, -1))  / array 범위 가져오기
                # r.expire(key, timedelta(15))

                json_rpt = json.dumps({"name": key, "delay": period, "address": value["source"], "timestamp": curr},
                                      ensure_ascii=False, ).encode("utf-8")
                print(json_rpt)
                r.set(value["vmd-specific"] + ":delay:" + key, json_rpt, 20)  #  20초 뒤에 만료/ period.total_seconds()
            else:
                print("packet arrived in", period)
            print("################################################################")
            # delayed_ied = [i.decode() for i in r.scan_iter("RPT:delay:*")]
            # print(key, ", list: ", delayed_ied)
        except KeyError as k:
            print("Report key:", k, "not exist yet")
            pass
        except AttributeError as a:
            print("AttributeError:", a)
            pass
        self.__dict__[key] = value


class RingBuffer(deque):
    """
    inherits deque, pops the oldest data to make room
    for the newest data when size is reached
    """

    def __init__(self, size):
        deque.__init__(self)
        self.size = size
        print("## RingBuffer created ##")

    def full_append(self, item):
        deque.append(self, item)
        # full, pop the oldest item, left most item
        self.popleft()

    def append(self, item):
        deque.append(self, item)
        # max size reached, append becomes full_append
        if len(self) == self.size:
            self.append = self.full_append

    def get(self):
        """returns a list of size items (newest items)"""
        return list(self)


class LiveCapture:
    def __init__(self, buff, redis_connection):
        self.circular = buff
        self.rpt = Report(r)
        self.r = redis_connection
        # self.timeCheck = datetime.utcnow().strftime('%y-%m-%d/%H:%M:%S.%f')
        # self.timeCheck = datetime.now()
        self.timeCheck = time.time()
        self.cron = False
        self.request = []
        self.response = []
        # 패킷 캡쳐 실행
        cap = pyshark.LiveCapture(interface='3', bpf_filter='tcp and port 102')  # GOOSE - ether proto 0x88B8
        # cap = pyshark.FileCapture('D:/dev/react-web-app/hmi_template/server/packet/mms/fresh.pcap', display_filter="mms or goose")

        cap.apply_on_packets(self.save)  # 각 패킷마다 save 함수 시행   / callback, timeout, packet_count

    def redisSetter(self, stamp, valueDict):
        # redis setter - timestamp 를 key 값으로 packet 값을 dictionary 로 redis 에 저장
        parse_dict = json.dumps(valueDict, ensure_ascii=False, ).encode("utf-8")  # redis 에 encoding 하여 저장
        self.r.set("packet" + stamp, parse_dict)

    def save(self, pkt):
        # stamp = datetime.fromtimestamp(time.time()) # .strftime('%Y-%m-%d %H:%M:%S.%f') - default format
        # stamp = datetime.utcnow().strftime('%y-%m-%d/%H:%M:%S.%f')
        # stamp = datetime.fromtimestamp(float(pkt.sniff_timestamp))
        stamp = float(pkt.sniff_timestamp)

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

            # 패킷의 특정 프로토콜 가져와서 dictionary 로 만들기
            mainArray = str(pkt.mms).replace("\t", "").split("\r\n")
            ethArray = str(pkt.eth).replace("\t", "").split("\r\n")

            # mms test
            # print(mainArray)

            # mainDict["key"] = mainArray[1]
            mainDict["timestamp"] = stamp

            # dictionary 에 배열안의 key, value 값 할당 중복을 고려 value값을 배열로
            self.dictSetter("mms", mainDict, mainArray)
            self.dictSetter("eth", ethDict, ethArray)

            mainDict["eth"] = ethDict

            # print("Packet Arrived!")
            # print(mainDict)
            # key, timestamp,. eth(Address[dest, src], Destination,  Source)

            # print(pkt)

            # redis setter
            # self.redisSetter(stamp, mainDict)

            # circular 버퍼에 패킷 저장, 주기적으로 처리
            self.circular.append(mainDict)

            # 각 ied report 발생주기 확인
            try:
                mainDict["vmd-specific"]
                if mainDict["vmd-specific"][0] == "RPT":
                    self.rpt[mainDict["visible-string"][0]] = {"vmd-specific": mainDict["vmd-specific"][0],
                                                               "timestamp": stamp,
                                                               "source": mainDict["eth"][0]["Source"][0]}
                    # { "utc-time": mainDict["utc-time"][0],

            except KeyError as k:
                # print(k)
                pass

            # 버퍼가 특정 수 이상 쌓이면 크론 실행
            if len(self.circular.get()) == 10:
                self.categorizing()

            # except 처리 확인
            """
            try:
                pkt.ip
            except AttributeError as e:
                pass
                print(e)
            with suppress(AttributeError):
                print("ip: ", pkt.ip)
            """
            # mms - negociatedParameterCBB : f100 하위 값
            #   1... .... = str1: True
            # 	.1.. .... = str2: True
        except AttributeError as e:
            # print(e)
            pass

    def categorizing(self):
        schedule = AsyncIOScheduler()

        # 실행할 함수
        def exec_cron():
            time_check = self.timeCheck
            # self.timeCheck = datetime.utcnow().strftime('%y-%m-%d/%H:%M:%S.%f')
            # self.timeCheck = datetime.now()
            self.timeCheck = time.time()
            # len([pkt for pkt in self.circular if pkt["timestamp"][0] >= self.timeCheck]) #  쌓인 패킷 길이

            stacked_array = [pkt for pkt in self.circular if pkt["timestamp"][0] >= time_check]
            # print(self.timeCheck, len(stacked_array), stacked_array, )

            # 패킷 분류 아래에 추가할 것! - request response 매칭
            # ied 연결 시작- initiate, confirmed, unconfirmed, ied 연결 종료 - conclude
            req = re.compile(r"(.+)-RequestPDU")
            res = re.compile(r"(.+)-ResponsePDU")
            # compare_array = stacked_array
            compare_array = []
            for (i, p) in enumerate(stacked_array):
                key = p["key"][0]
                # if p in req:
                if req.match(key):
                    # req_list.append(key)
                    try:
                        # if not p["eth"][0]["Address"][::-1] in [c["eth"][0]["Address"] for c in compare_array]:
                        if not p["invokeID"] in [c["invokeID"] for c in compare_array]:
                            compare_array.append(p)
                        else:
                            pass

                    except KeyError as e:
                        print("Request, Response not matched ", e)
                        """
                        if stacked_array[i]["eth"]["Address"] == stacked_array[i+1]["eth"]["Addrress"][::-1]:
                            continue
                        else:
                            print("Request, Response not matched")
                        """
                # elif res.match(key):
                #     res_list.append(key)
            # print("categorize on ", self.timeCheck)

            # 값이 남아있는 경우
            if len(compare_array) != 0:
                print("Something remains... ", compare_array)

        def rpt_cron():
            print(self.rpt)

        # cron 으로 주기적으로 패킷 처리
        # .add_job(exec.add_job(exec_interval, 'interval', seconds=1)
        schedule.add_job(exec_cron, 'cron', second="*")  # 매 초 분류
        # schedule.add_job(rpt_cron, 'cron', second="*/5")
        schedule.start()  # 시작

        # exec_cron()

    @staticmethod
    def dictSetter(filt, diction, array):  # array ('key : value') each value  to dict
        for (i, data) in enumerate(array):
            if filt == "mms":
                if i == 1:
                    if 'PDU' in data:
                        diction["key"] = data
                    else:
                        print("unknown key:", data)
                elif i == 2:
                    if "invokeID" in data:
                        attr = data.split(": ")
                        diction[attr[0]] = attr[1]
                else:
                    if ": " in data:
                        pass
                        attr = data.split(": ")
                        diction[attr[0]] = attr[1]
                    else:
                        diction["unknownKey"] = data
            else:
                if ": " in data:
                    attr = data.split(": ")
                    diction[attr[0]] = attr[1]
                else:
                    diction["unknown"] = data

        return diction


if __name__ == '__main__':
    # redis 연결
    r = redis.Redis(host="localhost", port=6379, db=0)

    # circular 버퍼
    mms_circular = RingBuffer(250)
    # stamp = datetime.utcnow().strftime('%y-%m-%d/%H:%M:%S.%f')[:]
    # r_keys = r.keys("packet-20-05-27/02:38:*") #  keys 비효율적

    # 주기적(cron)으로  regex에 맞춰 저장된 패킷 확인하기
    """ 
    r_keys = r.scan_iter("packet-20-05-27/02:*")
    for (idx, key) in enumerate(r_keys):
        get_dict = r.get(key).decode("utf-8")
        json_dict = dict(json.loads(get_dict))
        circular.append(key)
        # print(circular.get())
    """

    # list = [{'key': pkt.key, 'timestamp': pkt.timestamp} for pkt in circular.get()]
    # print(list)
    # print(circular.get())
    LiveCapture(mms_circular, r)
    # 최대 사이즈의 절반이상 이면 시작
    # 주기적으로 이전 마지막 timestamp 이후의 값들만 처리
