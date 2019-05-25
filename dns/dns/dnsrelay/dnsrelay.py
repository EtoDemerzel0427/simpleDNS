#!/usr/bin/python
# coding:utf-8

import socket
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
import struct
import select
import json
import logging
import time
from .ipsolve import *

"""
All DNS message have such format:

+---------------------+
|        Header       |
+---------------------+
|       Question      | the question for the name server
+---------------------+
|        Answer       | Resource Records (RRs) answering the question
+---------------------+
|      Authority      | RRs pointing toward an authority
+---------------------+
|      Additional     | RRs holding additional information
+---------------------+

For a query, we have only Header and Question parts.
All RRs have the same top level format shown below:

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

"""


class DnsRelay:
    def __init__(self, server_ip="8.8.8.8", config_file="zones.json", debug1=False, debug2=False, autosave=False):
        """
        :param server_ip: The IP address of a remote DNS server
        :param config_file: The local config file
        :param debug1: Turn on the first level debug info(boolean)
        :param debug2: Turn on the second level debug info(boolean)
        """
        self.server_ip = server_ip
        self.config_file = config_file
        self.debug1 = debug1
        self.debug2 = debug2
        self.autosave = autosave

        logging.basicConfig(filename='dns_relay.log',
                            format='[%(asctime)s-%(levelname)s: %(message)s]',
                            level=logging.DEBUG,
                            filemode='a',
                            datefmt='%Y-%m-%d %H:%M:%S')

        # UDP
        if self.debug1 or self.debug2:
            logging.info('*******************START*******************')
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # for linux socket 挂断连接不保留两分钟
        self.socket.bind(("127.0.0.1", 53))  # the local dns, listening to port 53
        if self.debug2:
            logging.info('Bound socket [127.0.0.1:53]')
            logging.info('Remote DNS server: [%s]' % server_ip)

        self.thread_pool = ThreadPoolExecutor(max_workers=None)  # determine by the processor number of the machine
        self.id_lock = Lock()  # the lock to access trans_dict
        self.socket_lock = Lock()
        self.file_lock = Lock()
        self.trans_dict = {}
        self.zones = {}
        self.starttime = time.time()

        # load data from local config file
        # self.local_data = self.load_data()
        self.zones = self.load_zones()
        print(self.zones)
        if self.debug2:
            logging.info('Data loaded.')

    def load_zones(self):
        try:
            with open(self.config_file) as f:
                zones = json.load(f)
                return zones
        except Exception as e:
            s = str(e)
            logging.info(s)

    def get_ip(self, msg, qtype):
        ansRR = msg[6:8]
        pos = len(self.get_qname(msg)[0]) + 20 - 1
        # print(msg[0:2])
        # ipv4
        if qtype == b'\x00\x01':
            if ansRR != b'\x00\x00':
                ip1, ip2, ip3, ip4 = struct.unpack('!BBBB', msg[-4::])
                return str(ip1) + '.' + str(ip2) + '.' + str(ip3) + '.' + str(ip4)
            else:
                return None
        # ipv6
        elif qtype == b'\x00\x1c':
            # if answer RRs > 1, there must be at least one ipv6 address
            if ansRR != b'\x00\x00':
                if ansRR != b'\x00\x01' or msg[pos:pos + 2] == b'\x00\x1c':
                    return msg[-16:-14].hex() + ':' + \
                           msg[-14:-12].hex() + ':' + \
                           msg[-12:-10].hex() + ':' + \
                           msg[-10:-8].hex() + ':' + \
                           msg[-8:-6].hex() + ':' + \
                           msg[-6:-4].hex() + ':' + \
                           msg[-4:-2].hex() + ':' + \
                           msg[-2::].hex()
                else:
                    return None
            else:
                return None

    def get_qname(self, msg):
        """
        :param msg: The DNS message
        :return:
        name - the URL
        """
        name_domain = msg[12:]  # the header is 12 bytes long
        i = 0
        num = name_domain[i]
        name_arr = []

        while not num == 0:
            # print(num)
            # print(name_domain[i+1: i+1+num])
            name_arr.append("".join(map(chr, name_domain[i + 1: i + 1 + num])))
            i += (1 + num)
            num = name_domain[i]

        name = '.'.join(name_arr)
        return name, i + 1 + 12

    def needremote(self, qname, qtype):
        if qname not in self.zones:
            return False
        timestape = time.time()

        if (len(self.zones[qname]["A"]) and self.zones[qname]["A"][0]["value"] == "0.0.0.0") \
                or (len(self.zones[qname]["AAAA"]) and self.zones[qname]["AAAA"][0]["addr"] == "0:0:0:0:0:0:0:0"):
            return True

        if qtype == b'\x00\x01':
            newA = []
            for item in self.zones[qname]["A"]:
                if "ts" in item.keys() and timestape - item["ts"] < item["ttl"]:
                    newA.append(item)
                elif "ts" not in item.keys() and timestape - self.starttime < item["ttl"]:
                    newA.append(item)
            self.zones[qname]["A"] = newA
            return len(newA)

        if qtype == b'\x00\x1c':
            newAAAA = []
            for item in self.zones[qname]["AAAA"]:
                if "ts" in item.keys() and timestape - item["ts"] < item["ttl"]:
                    newAAAA.append(item)
                elif "ts" not in item.keys() and timestape - self.starttime < item["ttl"]:
                    newAAAA.append(item)
            self.zones[qname]["AAAA"] = newAAAA
            return len(newAAAA)

    def handle_request(self):
        """
        flags are the first 8 bits of the following:
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        question:
        0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                                               |
        /                     QNAME                     /
        /                                               /
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                     QTYPE                     |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                     QCLASS                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        :param msg: the dns message
        :param addr:
        :return:
        """
        while True:
            try:
                msg, addr = self.socket.recvfrom(512)
                flags = msg[2:4]
                qname, pos = self.get_qname(msg)

                qtype = msg[pos: pos + 2]
                qclass = msg[pos + 2: pos + 4]
                # ipv4
                # if (flags == b'\x01\x00' or flags == b'\x00\x00') and qtype == b'\x00\x01' and qclass == b'\x00\x01':
                if (flags[0] == 0 or flags[0] == 1) and qtype == b'\x00\x01' and qclass == b'\x00\x01':
                    if self.debug1 or self.debug2:
                        logging.info('DNS Query address: %s  Query name: %s', addr, qname)
                    if self.needremote(qname, qtype):
                        # logging
                        if self.debug1 or self.debug2:
                            logging.info("(IPV4)Found " + qname + " in local DNS file.")

                        v4_addrs = self.zones[qname]["A"]  # v4_addrs is a list which stores all v4 addresses of qname
                        if len(v4_addrs) != 0:
                            response = self.create_response(msg, v4_addrs)

                            self.socket.sendto(response, addr)
                    else:
                        if self.debug2:
                            logging.info("(LOCAL)not found qname: " + qname)
                        # not found in local file, so do relay here.
                        self.thread_pool.submit(self.remote_dns, msg, addr, qtype)
                # ipv6
                elif (flags[0] == 0 or flags[0] == 1) and qtype == b'\x00\x1c' and qclass == b'\x00\x01':
                    if self.needremote(qname, qtype):
                        # print("Found " + qname + ": " + self.local_data[qname])
                        if self.debug1 or self.debug2:
                            logging.info("(IPV6)Found " + qname + " in local DNS file.")

                        v6_addrs = self.zones[qname]["AAAA"]

                        if len(v6_addrs) != 0:
                            response = self.create_response_ipv6(msg, v6_addrs)

                            self.socket.sendto(response, addr)
                    else:
                        if self.debug2:
                            logging.info("(LOCAL)not found qname: " + qname)
                        # not found in local file, so do relay here.
                        self.thread_pool.submit(self.remote_dns, msg, addr, qtype)

            except Exception as e:
                print('error is ', e)

    def create_response(self, msg, addr_list):
        """
        Create a response message to answer a query message
        :param msg: the query message
        :param addr_list: a list which contains all ips for a qname
        :return: a dns response message
        """

        # header
        id = msg[0:2]

        if len(addr_list) == 0:
            raise ValueError("Addr_list is supposed to be non-empty.")

        if addr_list[0]["value"] == "0.0.0.0":
            flags = b'\x81\x83'  # RCODE=3, referring error
            ancount = b'\x00\x00'  # no RR in answer section
            print("The domain is blocked!")
        else:
            flags = b'\x81\x80'  # RCODE=0
            ancount = len(addr_list).to_bytes(2, "big")  # answer RR number
            # print(ancount)
        qdcount = b'\x00\x01'  # question number = 1
        nscount = b'\x00\x00'  # no RR in authority record section
        arcount = b'\x00\x00'  # no RR in additional section

        header = id + flags + qdcount + ancount + nscount + arcount

        # question
        question = msg[12:]

        if flags == b'\x81\x83':
            return header + question

        # answer
        res = header + question
        for item in addr_list:
            name = b'\xc0\x0c'  # compression, only the offset is stored here
            qtype = b'\x00\x01'  # A record
            qclass = b'\x00\x01'  # IN
            ttl = item["ttl"].to_bytes(4, "big")  # TTL
            data_len = b'\x00\x04'

            ip = item["value"].split('.')
            addr = struct.pack('!BBBB', int(ip[0]), int(ip[1]), int(ip[2]), int(ip[3]))
            answer_rr = name + qtype + qclass + ttl + data_len + addr
            res += answer_rr

        return res

    def create_response_ipv6(self, msg, addr_list):
        """
        Create a response message to answer a query message
        :param msg: the query message
        :param ip: the ip found via our local dns
        :return: a dns response message
        """

        # header
        id = msg[0:2]

        if len(addr_list) == 0:
            raise ValueError("Addr_list is supposed to be non-empty.")

        if addr_list[0]["addr"] == "0:0:0:0:0:0:0:0":
            flags = b'\x81\x83'  # RCODE=3, referring error
            ancount = b'\x00\x00'  # no RR in answer section
            print("The domain is blocked!")
        else:
            flags = b'\x81\x80'  # RCODE=0
            ancount = len(addr_list).to_bytes(2, "big")  # answer RR number
            # print(ancount)
        qdcount = b'\x00\x01'  # question number = 1
        nscount = b'\x00\x00'  # no RR in authority record section
        arcount = b'\x00\x00'  # no RR in additional section

        header = id + flags + qdcount + ancount + nscount + arcount

        # question
        question = msg[12:]

        if flags == b'\x81\x83':
            return header + question

        # answer
        res = header + question
        for item in addr_list:
            name = b'\xc0\x0c'  # compression, only the offset is stored here
            qtype = b'\x00\x1c'  # AAAA record
            qclass = b'\x00\x01'  # IN
            ttl = item["ttl"].to_bytes(4, "big")  # TTL
            data_len = b'\x00\x10'

            addr = v62b(item["addr"])
            answer_rr = name + qtype + qclass + ttl + data_len + addr
            res += answer_rr
        return res

    def remote_dns(self, msg, addr, qtype):
        # choose an ID
        # our method is, using the same id, if not availble id = (id + 1) % 65535
        # print("The self.zone's length: ", len(self.zones))
        with self.id_lock:
            orig_id = int.from_bytes(msg[:2], "big")
            trans_id = orig_id
            print('orig_id:', orig_id)
            print('trans_id:', trans_id)
            while trans_id in self.trans_dict:
                trans_id = (trans_id + 1) % 65535

            self.trans_dict[trans_id] = orig_id
            # print('ADD', self.trans_dict.items())
            new_msg = trans_id.to_bytes(2, "big") + msg[2:]

        # send dns request to remote dns server
        remote_addr = (self.server_ip, 53)
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        remote_socket.sendto(new_msg, remote_addr)
        if self.debug2:
            logging.info('Send DNS request to %s', self.server_ip)
        # waiting until time out
        # reference: https://stackoverflow.com/questions/2719017/how-to-set-timeout-on-pythons-socket-recv-method
        remote_socket.setblocking(False)
        ready = select.select([remote_socket], [], [], 3.5)
        ans = None
        if ready[0]:
            ans, _ = remote_socket.recvfrom(512)
            # TODO： Put this info to log file
            if qtype == b'\x00\x01' and self.debug2:
                logging.info('Received the IPV4 answer from remote server.')
            elif qtype == b'\x00\x1c' and self.debug2:
                logging.info('Received the IPV6 answer from remote server.')
            # print('\nReceived\n')
        else:
            # todo: put this info to log file
            if self.debug1 or self.debug2:
                logging.info('*******************TIME OUT****************')
            print('*******************TIME OUT****************')
            del self.trans_dict[trans_id]
            # print('DEL', self.trans_dict.items())
        remote_socket.close()

        with self.socket_lock, self.id_lock:
            # received remote packet
            if ready[0]:

                remote_id = int.from_bytes(ans[:2], "big")
                assert remote_id == trans_id

                local_id = self.trans_dict[remote_id]
                assert local_id == orig_id

                local_msg = local_id.to_bytes(2, "big") + ans[2:]
                # print('orig_id:', orig_id)
                # print('trans_id:', trans_id)
                # print('the local msg:', local_msg)
                # print('addr:', addr)
                # with self.socket_lock:

                # update the dns local data
                qname, _ = self.get_qname(msg)
                RR_num = int.from_bytes(ans[6:8], "big")
                # if RR_num == 0:
                #     if qname not in self.zones:
                #         print("the RR number of ", qname, "is zero.")
                #         self.zones[qname] = {}
                #         self.zones[qname]["A"] = [{"ttl": 400, "value": "0.0.0.0"}]
                #         self.zones[qname]["AAAA"] = [{"ttl": 400, "addr": "0:0:0:0:0:0:0:0"}]

                # print(self.zones)
                ans_ptr = len(msg)
                for i in range(RR_num):
                    ans_ptr += 2  # skip name
                    atype = ans[ans_ptr:ans_ptr + 2]
                    # print("atype is:", atype)
                    if atype == b'\x00\x01':
                        # print("IPV4 RECORD TO ADD")
                        ans_ptr += 4  # skip type and class IN
                        attl = int.from_bytes(ans[ans_ptr:ans_ptr + 4], "big")

                        ans_ptr += 4  # skip to data length
                        data_len = int.from_bytes(ans[ans_ptr:ans_ptr + 2], "big")

                        ans_ptr += 2  # skip to address

                        ip1, ip2, ip3, ip4 = struct.unpack('!BBBB', ans[ans_ptr:ans_ptr + data_len])
                        addr_str = str(ip1) + '.' + str(ip2) + '.' + str(ip3) + '.' + str(ip4)

                        ans_ptr += data_len
                        if qname not in self.zones:
                            self.zones[qname] = {}
                            self.zones[qname]["A"] = [{"ttl": attl, "value": addr_str, "ts": time.time()}]
                            self.zones[qname]["AAAA"] = []
                        else:
                            self.zones[qname]["A"].append({"ttl": attl, "value": addr_str, "ts": time.time()})
                        print("(IPV4)" + qname + ": " + addr_str)
                    elif atype == b'\x00\x1c':
                        # print("IPV6 RECORD TO ADD")
                        ans_ptr += 4  # skip type and class IN
                        attl = int.from_bytes(ans[ans_ptr:ans_ptr + 4], "big")

                        ans_ptr += 4  # skip to data length
                        data_len = int.from_bytes(ans[ans_ptr:ans_ptr + 2], "big")

                        ans_ptr += 2  # skip to address
                        addr_str = b2v6(ans[ans_ptr:ans_ptr + data_len])

                        ans_ptr += data_len
                        if qname not in self.zones:
                            self.zones[qname] = {}
                            self.zones[qname]["AAAA"] = [{"ttl": attl, "addr": addr_str, "ts": time.time()}]
                            self.zones[qname]["A"] = []
                        else:
                            self.zones[qname]["AAAA"].append({"ttl": attl, "addr": addr_str, "ts": time.time()})
                        print("(IPV6)" + qname + ": " + addr_str)
                    else:
                        # simply skip the whole RR
                        # print("SKIP RECORD.")
                        ans_ptr += 8
                        data_len = int.from_bytes(ans[ans_ptr: ans_ptr + 2], "big")
                        ans_ptr += (2 + data_len)

                if RR_num == 0:
                    if qname not in self.zones:
                        # print("the RR number of ", qname, "is zero.")
                        self.zones[qname] = {}
                        self.zones[qname]["A"] = [{"ttl": 400, "value": "0.0.0.0"}]
                        self.zones[qname]["AAAA"] = [{"ttl": 400, "addr": "0:0:0:0:0:0:0:0"}]

                if self.autosave:
                    with self.file_lock:
                        with open(self.config_file, 'w') as fout:
                            # print("writing to file!")
                            json.dump(self.zones, fout)

                self.socket.sendto(local_msg, addr)

                if self.debug1 or self.debug2:
                    if self.get_ip(ans, qtype) is not None:
                        # print(self.get_ip(ans, qtype))
                        if qtype == b'\x00\x01':
                            logging.info("(IPV4)Found %s : %s", self.get_qname(msg)[0], self.get_ip(ans, qtype))
                        elif qtype == b'\x00\x1c':
                            logging.info("(IPV6)Found %s : %s", self.get_qname(msg)[0], self.get_ip(ans, qtype))
                    else:
                        if qtype == b'\x00\x01':
                            logging.info("(IPV4)Not Found %s IPV4 Address!", self.get_qname(msg)[0])
                        elif qtype == b'\x00\x1c':
                            logging.info("(IPV6)Not Found %s IPV6 Address!", self.get_qname(msg)[0])
                if self.debug2:
                    logging.info('Send the answer to query address.')
                del self.trans_dict[remote_id]
                # print('DEL', self.trans_dict.items())

    # def run(self):
    #     while True:
    #         # in the RFC standard, packets less than 512 bytes are recommended to use UDP.
    #         # so we assume our packets are less than that length.
    #         msg, addr = self.socket.recvfrom(512)
    #
    #         self.thread_pool.submit(self.handle_request, msg, addr)
    #         # self.handle_request(msg, addr)
    #
    # def __del__(self):
    #     # print("I am destructor!")
    #     with open(self.config_file, "w") as f:
    #         json.dump(self.zones, f)


if __name__ == '__main__':
    dns = DnsRelay(server_ip='192.168.113.1')
    dns.handle_request()
