import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # 소켓생성
ip = socket.gethostbyname(socket.getfqdn())
sock.bind((ip, 8080))  # 서버 아이피및 포트 지정 - tuple / 데이터를 받기위해 필요

while True:
    msg = input("input:")  # test data
    sock.sendto(msg.encode(), ('192.168.0.29', 7070))  # 문자열 인코딩 후 서버로 전송
    # data, addr = sock.recvfrom(200)  # 데이터 수신 대기 (최대 200Byte)
    # # sock.sendto(data, addr)
    # print("Server is received data:", data.decode())  # 받은 데이터 출력
    # print("Sent Client IP:", addr[0])  # 보내온 클라이언트 아이피
    # print("Sent Client Port:", addr[1])  # 보내온 클라이언트 포트 (랜덤)
    # print("Server return data to", addr[0])


