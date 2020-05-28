import time
from datetime import datetime
import pyshark
import redis
import json
from crontab import CronTab
from collections import deque


class Dictlist(dict):
    def __setitem__(self, key, value):
        try:
            self[key]
        except KeyError:
            super(Dictlist, self).__setitem__(key, [])
        self[key].append(value)


class RingBuffer(deque):
    """
    inherits deque, pops the oldest data to make room
    for the newest data when size is reached
    """

    def __init__(self, size):
        deque.__init__(self)
        self.size = size

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


if __name__ == '__main__':
    r = redis.Redis(host="localhost", port=6379, db=0)
    circular = RingBuffer(5)
    # stamp = datetime.utcnow().strftime('%y-%m-%d/%H:%M:%S.%f')[:]
    # r_keys = r.keys("packet-20-05-27/02:38:*")
    r_keys = r.scan_iter("packet-20-05-27/02:*")
    for (idx, key) in enumerate(r_keys):
        get_dict = r.get(key).decode("utf-8")
        json_dict = dict(json.loads(get_dict))
        circular.append(key)
        # print(circular.get())

    # list = [{'key': pkt.key, 'timestamp': pkt.timestamp} for pkt in circular.get()]
    # print(list)
    print(circular.get())

    # 최대 사이즈의 절반이상 이면 시작
    # 주기적으로 이전 마지막 timestamp 이후의 값들만 처리
