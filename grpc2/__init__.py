import grpc
import time
from concurrent import futures
import sys
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.all import *

sys.path.append('example')

from example import data_pb2, data_pb2_grpc

_ONE_DAY_IN_SECONDS = 60 * 60 * 24
_HOST = '20.26.217.12'
_PORT = '8080'
TaskDict = {}


def CreatPacket(TaskDict):
    INTpkt = IP(dst=TaskDict['dIP']) / UDP(sport=int(TaskDict['sPORT']), dport=int(TaskDict['dPORT'])) / "INTdata"
    send(INTpkt, inter=int(TaskDict['freq']))


class FormatData(data_pb2_grpc.FormatDataServicer):
    def DoFormat(self, request, context):
        TaskDict['taskID'] = request.taskID
        TaskDict['freq'] = request.freq
        TaskDict['metadata'] = request.metadata
        TaskDict['sIP'] = request.sIP
        TaskDict['dIP'] = request.dIp
        TaskDict['sPORT'] = request.sPORT
        TaskDict['dPORT'] = request.dPORT
        TaskDict['protocol'] = request.protocol
        print(TaskDict)
        # CreatPacket(TaskDict)

        return data_pb2.Success(success="Received successfully")


def serve():
    grpcServer = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    data_pb2_grpc.add_FormatDataServicer_to_server(FormatData(), grpcServer)
    grpcServer.add_insecure_port(_HOST + ':' + _PORT)
    grpcServer.start()
    try:
        while True:
            time.sleep(_ONE_DAY_IN_SECONDS)
    except KeyboardInterrupt:
        grpcServer.stop(0)


if __name__ == '__main__':
    serve()

