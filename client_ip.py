import os
import socket
from threading import Thread
import subprocess
import time
import wx

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # 소켓생성
ip = socket.gethostbyname(socket.getfqdn())  # 실행되는 pc의 ip
sock.bind((ip, 7080))  # 서버 IP 및 포트 지정 - tuple type

EVT_RESULT_ID = wx.ID_EDIT


def alignToBottomRight(win):  # wx.frame 위치를 우하단으로
    dw, dh = wx.DisplaySize()
    w, h = win.GetSize()
    x = dw - w
    y = dh - h
    win.SetPosition((x+5, y - 35))


class ResultEvent(wx.PyEvent):
    """Simple event to carry arbitrary result data."""

    def __init__(self, data):
        """Init Result Event."""
        wx.PyEvent.__init__(self)
        self.SetEventType(EVT_RESULT_ID)
        self.data = data


# Thread class that executes processing
class WorkerThread(Thread):
    """Worker Thread Class."""

    def __init__(self, notify_window):
        """Init Worker Thread Class."""
        Thread.__init__(self)
        self._notify_window = notify_window
        self._want_abort = 0
        self.daemon = True  # daemon - 프로그램 종료시 데몬 쓰레드 종료
        # This starts the thread running on creation, but you could
        # also make the GUI thread responsible for calling this
        self.start()

    def run(self):
        """Run Worker Thread."""
        # This is the code executing in the new thread. Simulation of
        # a long process (well, 10s here) as a simple loop - you will
        # need to structure your processing so that you periodically
        # peek at the abort variable

        while True:
            if self._want_abort:
                print("Aborted")
                break
            data, addr = sock.recvfrom(512)  # 데이터 수신 대기 (최대 200Byte)
            if data:
                self._notify_window.Iconize(False)

                print("Client send and recieved data:", data.decode())
                print("data from ip", addr[0])
                print("data from PORT:", addr[1])
                print(data.decode())
                self._notify_window.SetStatusText(data)
                time.sleep(5)
                self._notify_window.Iconize(True)
                wx.PostEvent(self._notify_window, ResultEvent(None))

    def abort(self):
        """abort worker thread."""
        # Method for use by main thread to signal an abort
        self._want_abort = 1


class BaseFrame(wx.Frame):
    def __init__(self, parent, title):
        super(BaseFrame, self).__init__(parent, title=title, size=(700, 60),
                                        style=wx.DEFAULT_FRAME_STYLE | wx.STAY_ON_TOP)
        self.statusbar = self.CreateStatusBar(1)
        self.statusbar.SetStatusText('>>')
        self.Bind(wx.EVT_CLOSE, self.OnClose)

        self.InitUI()

    def InitUI(self):
        self.worker = WorkerThread(self)
        self.SetIcon(wx.Icon('serverstat.ico', wx.BITMAP_TYPE_ICO))
        self.Show()

    def OnClose(self, event):
        print("Server Status Closed")
        self.worker.abort()
        # self.Close()
        # self.worker.join()  # Non-daemon thread 일시 작업 종료 후 프로그램 종료
        self.Destroy()  # you may also do:  event.Skip()


def main():
    """
    filename = os.path.splitext(os.path.basename(__file__))[0]

    with subprocess.Popen(f"tasklist | findstr {filename}.exe", stdout=subprocess.PIPE, shell=True) as process:
        if len(process.stdout.readlines()):
            print(f"Server Stat Process Already Exist: {filename}.exe")
        else:
        """

    app = wx.App(0)
    bp = BaseFrame(None, title="Server Status ("+str(ip)+")")
    alignToBottomRight(bp)  # 화면 우하단에 위치
    app.MainLoop()


if __name__ == '__main__':
    main()
