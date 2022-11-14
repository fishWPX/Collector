import sys
import base64
from scapy.all import (
    FieldLenField,
    IntField,
    # IPOption,
    Packet,
    PacketListField,
    ShortField,
    get_if_list,
    sniff
)
from scapy.layers.inet import _IPOption_HDR




class pc_int_t(object):

    def __init__(self, version, next_proto, type, reserved, hw_id, seq_number, timestamp, switch_id, pad0,
                 ingress_port, pad1, egress_port, pad2, queue_id, pad3, queue_occupancy, timestamp_out):
        self.version = version
        self.next_proto = next_proto
        self.type = type
        self.reserved = reserved
        self.hw_id = hw_id
        self.seq_number = seq_number
        self.timestamp = timestamp
        self.switch_id = switch_id

        self.pad0 = pad0
        self.ingress_port = ingress_port
        self.pad1 = pad1
        self.egress_port = egress_port
        self.pad2 = pad2
        self.queue_id = queue_id

        self.pad3 = pad3
        self.queue_occupancy = queue_occupancy
        self.timestamp_out = timestamp_out

class drop_int_t(object):

    def __init__(self, version, next_proto, type, reserved, hw_id, seq_number, timestamp, switch_id, pad0,
                 ingress_port, pad1, egress_port, pad2, queue_id, drop_reason, reserved_):
        self.version = version
        self.next_proto = next_proto
        self.type = type
        self.reserved = reserved
        self.hw_id = hw_id
        self.seq_number = seq_number
        self.timestamp = timestamp
        self.switch_id = switch_id

        self.pad0 = pad0
        self.ingress_port = ingress_port
        self.pad1 = pad1
        self.egress_port = egress_port
        self.pad2 = pad2
        self.queue_id = queue_id

        self.drop_reason = drop_reason
        self.reserved_ = reserved_

class pc_int_protocol:
    version = (0, 3)
    next_proto = (4, 7)
    type = (8, 10)
    reserved = (11, 25)
    hw_id = (26, 31)

    seq_number = (32, 63)
    timestamp = (64, 95)
    switch_id = (96, 127)

    pad0 = (128, 134)
    ingress_port = (135, 143)
    pad1 = (144, 150)
    egress_port = (151, 159)

    pad2 = (160, 162)
    queue_id = (163, 167)
    pad3 = (168, 172)
    queue_occupancy = (173, 191)
    timestamp_out = (192, 223)

class drop_int_protocol:
    version = (0, 3)
    next_proto = (4, 7)
    type = (8, 10)
    reserved = (11, 25)
    hw_id = (26, 31)

    seq_number = (32, 63)
    timestamp = (64, 95)
    switch_id = (96, 127)

    pad0 = (128, 134)
    ingress_port = (135, 143)
    pad1 = (144, 150)
    egress_port = (151, 159)

    pad2 = (160, 162)
    queue_id = (163, 167)
    drop_reason = (168, 175)
    reserved_ = (176, 191)


def my_hex2bin(s):
    bin_s = bin(int(s, 16))
    bin_s = bin_s[2:len(bin_s)]
    return bin_s.zfill(4)





# parsing postcard/queue packet
def pc_pkt_parser(int_load):
    # 28Bytes=56B
    INT_LEN = 56

    # int_load = '100000000000000012ebbda200000001000200030001000000020000000300000004000000554450'

    int_load = str(int_load)[0:INT_LEN]
    # hex to binary
    int_load_bin = ''
    for s in int_load:
        int_load_bin += my_hex2bin(s)
    # int_load_bin = bin(int(int_load, 16))
    version = int(int_load_bin[pc_int_protocol.version[0]:pc_int_protocol.version[1]+1], 2)
    next_proto = int(int_load_bin[pc_int_protocol.next_proto[0]:pc_int_protocol.next_proto[1]+1], 2)
    type = int(int_load_bin[pc_int_protocol.type[0]:pc_int_protocol.type[1]+1], 2)
    reserved = int(int_load_bin[pc_int_protocol.reserved[0]:pc_int_protocol.reserved[1]+1], 2)
    hw_id = int(int_load_bin[pc_int_protocol.hw_id[0]:pc_int_protocol.hw_id[1]+1], 2)
    seq_number = int(int_load_bin[pc_int_protocol.seq_number[0]:pc_int_protocol.seq_number[1]+1], 2)
    timestamp = int(int_load_bin[pc_int_protocol.timestamp[0]:pc_int_protocol.timestamp[1]+1], 2)
    switch_id = int(int_load_bin[pc_int_protocol.switch_id[0]:pc_int_protocol.switch_id[1]+1], 2)
    pad0 = int(int_load_bin[pc_int_protocol.pad0[0]:pc_int_protocol.pad0[1]+1], 2)
    ingress_port = int(int_load_bin[pc_int_protocol.ingress_port[0]:pc_int_protocol.ingress_port[1]+1], 2)
    pad1 = int(int_load_bin[pc_int_protocol.pad1[0]:pc_int_protocol.pad2[1]+1], 2)
    egress_port = int(int_load_bin[pc_int_protocol.egress_port[0]:pc_int_protocol.egress_port[1]+1], 2)
    pad2 = int(int_load_bin[pc_int_protocol.pad2[0]:pc_int_protocol.pad2[1]+1], 2)
    queue_id = int(int_load_bin[pc_int_protocol.queue_id[0]:pc_int_protocol.queue_id[1]+1], 2)
    pad3 = int(int_load_bin[pc_int_protocol.pad3[0]:pc_int_protocol.pad3[1]+1], 2)
    queue_occupancy = int(int_load_bin[pc_int_protocol.queue_occupancy[0]:pc_int_protocol.queue_occupancy[1]+1], 2)
    timestamp_out = int(int_load_bin[pc_int_protocol.timestamp_out[0]:pc_int_protocol.timestamp_out[1]+1], 2)


    int_tmp = pc_int_t(version=version, next_proto=next_proto, type=type, reserved=reserved, hw_id=hw_id,
                    seq_number=seq_number, timestamp=timestamp, switch_id=switch_id, pad0=pad0,
                    ingress_port=ingress_port, pad1=pad1, egress_port=egress_port,
                    pad2=pad2, queue_id=queue_id, pad3=pad3, queue_occupancy=queue_occupancy, timestamp_out=timestamp_out)
    return int_tmp.__dict__

    # for key in int_tmp.keys():
    #     print(key,':',int_tmp[key])
    # print(int_tmp)

def drop_pkt_parser(int_load):
    # 24Bytes=48B
    INT_LEN = 48

    # int_load = '100000000000000012ebbda200000001000200030001000000020000000300000004000000554450'
    int_load = str(int_load)[0:INT_LEN]

    int_load_bin = bin(int(int_load, 16))

    version = int(int_load_bin[drop_int_protocol.version[0]:drop_int_protocol.version[1]], 2)

    next_proto = int(int_load_bin[drop_int_protocol.next_proto[0]:drop_int_protocol.next_proto[1]], 2)
    type = int(int_load_bin[drop_int_protocol.type[0]:drop_int_protocol.type[1]], 2)
    reserved = int(int_load_bin[drop_int_protocol.reserved[0]:drop_int_protocol.reserved[1]], 2)
    hw_id = int(int_load_bin[drop_int_protocol.hw_id[0]:drop_int_protocol.hw_id[1]], 2)
    seq_number = int(int_load_bin[drop_int_protocol.seq_number[0]:drop_int_protocol.seq_number[1]], 2)
    timestamp = int(int_load_bin[drop_int_protocol.timestamp[0]:drop_int_protocol.timestamp[1]], 2)
    switch_id = int(int_load_bin[drop_int_protocol.switch_id[0]:drop_int_protocol.switch_id[1]], 2)
    pad0 = int(int_load_bin[drop_int_protocol.pad0[0]:drop_int_protocol.pad0[1]], 2)
    ingress_port = int(int_load_bin[drop_int_protocol.ingress_port[0]:drop_int_protocol.ingress_port[1]], 2)
    pad1 = int(int_load_bin[drop_int_protocol.pad1[0]:drop_int_protocol.pad2[1]], 2)
    egress_port = int(int_load_bin[drop_int_protocol.egress_port[0]:drop_int_protocol.egress_port[1]], 2)
    pad2 = int(int_load_bin[drop_int_protocol.pad2[0]:drop_int_protocol.pad2[1]], 2)
    queue_id = int(int_load_bin[drop_int_protocol.queue_id[0]:drop_int_protocol.queue_id[1]], 2)
    drop_reason = int(int_load_bin[drop_int_protocol.drop_reason[0]:drop_int_protocol.drop_reason[1]], 2)
    reserved_ = int(int_load_bin[drop_int_protocol.reserved_[0]:drop_int_protocol.reserved_[1]], 2)



    int_tmp = drop_int_t(version=version, next_proto=next_proto, type=type, reserved=reserved, hw_id=hw_id,
                    seq_number=seq_number, timestamp=timestamp, switch_id=switch_id, pad0=pad0,
                    ingress_port=ingress_port, pad1=pad1, egress_port=egress_port,
                    pad2=pad2, queue_id=queue_id, drop_reason=drop_reason, reserved_=reserved_)
    return int_tmp.__dict__

    # for key in int_tmp.keys():
    #     print(key,':',int_tmp[key])
    # print(int_tmp)



def handle_pkt(pkt):

    LOAD = str(pkt[3].load.hex())
    print('================================================DTEL Report==================================================================')
    INT_LEN = 56
    int_load = LOAD[0:INT_LEN]
    int_info = pc_pkt_parser(int_load)
    for key in int_info.keys():
        print(key, ':', int_info[key])

    print('========================================Computing Performance Information======================================================')
    cmp_load = LOAD[INT_LEN+84:len(LOAD)]
    cmp_load = str(base64.b16decode(cmp_load.upper()), 'utf-8')
    print(cmp_load)


    print('=================================================================================================================================')


    # # Computing Performance Information
    # print("got a packet")
    # print('================================================Computing Performance Information==================================================================')
    # if pkt.haslayer("UDP"):
    #     cmp_int = str(pkt["UDP"].payload)
    #     cmp_int = cmp_int[2:len(cmp_int) - 1]
    #     print(cmp_int)
    #sys.stdout.flush()








if __name__ == '__main__':

    # mysql_db = MySQLDatabase("guest", host="10.112.57.255", port=3306, user="root", passward="123456")
    # mysql_db.connect()
    # tmp = pc_pkt_parser('pkt')
    # for key in tmp.keys():
    #     print(key, ':', tmp[key])
    #

    iface = sys.argv[1]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(filter="udp and port 32766", iface=iface,
          prn=lambda x: handle_pkt(x))

    # test_load = '0220000100000022eb8dc696000000660053005200000002eb8dc8b6898989890000293984'
    #
    # tmp = pc_pkt_parser(test_load)
    # for key in tmp.keys():
    #     print(key, ':', tmp[key])




