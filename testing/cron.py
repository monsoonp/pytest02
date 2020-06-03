import schedule
import time
from crontab import CronTab


def job():
    print("I'm working...")

# schedule.every(10).minutes.do(job)
# schedule.every().hour.do(job)
# schedule.every().day.at("10:30").do(job)
# schedule.every().second.do(job)
from apscheduler.schedulers.blocking import BlockingScheduler

# 실행할 함수
def exec_interval():
    print('exec interval')

def exec_cron():
    print('exec cron')


print([1,2]==[2,1][::-1])
print(len([]))


sched = BlockingScheduler()
# 예약방식 interval로 설정, 10초마다 한번 실행
sched.add_job(exec_interval, 'interval', seconds=1)

sched.start()