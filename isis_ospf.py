# L2 communication extension for Open Networking Laboratory (ONOS) Controller.
# protocol supported: ISIS, OSPF
#
# ONOS
#------------------------------------------
# Copyright 2016 Open Networking Laboratory
#
# Author: Nicklesh Adlakha <nicklesh.adlakha@gmail.com>
# copyright (c) 2017 by Nicklesh Adlakha
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from sys import platform, argv, exit, stderr

""" This is strictly for Linux and requires python3"""
if platform.lower() != 'linux':
    exit(1)

protocol_flag = 0
SPORT = 0
OSPFSPORT = 7000
ISISSPORT = 3000

if argv.__len__() != 2:
    print("Usage: python3 %s [isis|ospf]" % argv[0], file=stderr)
    exit(2)
else:
    if argv[1].lower() == 'isis':
        protocol_flag = 1
        SPORT = ISISSPORT
    elif argv[1].lower() == 'ospf':
        SPORT = OSPFSPORT
    else:
        print("protocol not supported", file=stderr)
        exit(110)

from socket import socket, AF_PACKET, AF_INET, SOCK_RAW, SOCK_STREAM, htons, SOL_SOCKET, if_nametoindex, SO_REUSEADDR, \
    SO_KEEPALIVE, inet_ntoa
from os import execlp
from struct import pack
import ctypes
import threading
from signal import signal, SIGALRM, pthread_kill

ETH_P_ALL = 0x0003
ETH_FRAME_LEN = 1514
ETH_A_LEN = 6
SO_ATTACH_FILTER = 26
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_DROP_MEMBERSHIP = 2
PACKET_MR_MULTICAST = 0
PACKET_OUTGOING = 4
L1_LAN  = 0x0f
L1_LSP  = 0x12
L1_CSNP = 0x18
L1_PSNP = 0x1a
ISIS_CONFIG_PACKET_TYPE  = 0xFF
pdu_length = 0
L1 = 0
L2 = 1
P2P = 2
L1NL2 = 3
SHOST = "localhost"
rawsock = 0
csock = 0
ospf_wsock = 0
loop = True
wthread = ""

mtuple  =    (
                [0x01, 0x80, 0xC2, 0x00, 0x00, 0x14], # L1 Multicast Address
                [0x01, 0x80, 0xC2, 0x00, 0x00, 0x15], # L2 Multicast Address
                [0x09, 0x00, 0x2b, 0x00, 0x00, 0x05], # P2P Multicast Address
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x00], # null entry
                [0x01, 0x00, 0x5e, 0x00, 0x00, 0x05], # OSPF address
                [0x01, 0x00, 0x5e, 0x00, 0x00, 0x06] # OSPF address
            )

filter_code = (
                [0x28, 0, 0, 0x0000000c],
                [0x25, 6, 0, 0x000005dc],
                [0x28, 0, 0, 0x0000000e],
                [0x15, 0, 4, 0x0000fefe],
                [0x30, 0, 0, 0x00000010],
                [0x15, 0, 2, 0x00000003],
                [0x30, 0, 0, 0x00000011],
                [0x15, 4, 0, 0x00000083],
                [0x28, 0, 0, 0x0000000c],
                [0x15, 0, 3, 0x00000800],
                [0x30, 0, 0, 0x00000017],
                [0x15, 0, 1, 0x00000059],
                [0x6, 0, 0, 0x00040000],
                [0x6, 0, 0, 0x00000000]
              )

fdata = bytes()

for lfd in filter_code:
    fdata += pack('HBBI', lfd[0], lfd[1], lfd[2], lfd[3])

mdata = ctypes.create_string_buffer(fdata)
packdata = pack('HP', filter_code.__len__(), ctypes.addressof(mdata))

import netifaces

ifdata = {}

for nif in netifaces.interfaces():
    if nif.lower() == 'lo':
        continue
    else:
        hwaddrhex = netifaces.ifaddresses(nif)[netifaces.AF_LINK][0]['addr']
        iindex = if_nametoindex(nif)
        ifdata[iindex] = {'if_name' : nif, 'mac': bytearray.fromhex("".join(hwaddrhex.split(':')))}

def signal_handler(signum, frame):
    pass

signal(SIGALRM, signal_handler)

def thread_callback():
    try:
        pktbuff = bytearray(ETH_FRAME_LEN + ETH_A_LEN + 1)
        plen = ETH_FRAME_LEN + ETH_A_LEN + 1

        if protocol_flag:
            while loop:
                zn, iinfo = rawsock.recvfrom_into(pktbuff, ETH_FRAME_LEN, 0)

                if iinfo[2] == PACKET_OUTGOING:
                    continue

                if pktbuff[17] == 0x83:
                    lindex = if_nametoindex(iinfo[0])

                    if ifdata[lindex]['type'] == L1NL2:
                        if pktbuff[:6] != bytes(mtuple[L1]) and pktbuff[:6] != bytes(mtuple[L2]):
                            continue
                    elif ifdata[lindex]['type'] >= 0:
                        if pktbuff[:6] != bytes(mtuple[ifdata[lindex]['type']]):
                            continue
                    else:
                        continue

                    pktbuff[ETH_FRAME_LEN:ETH_FRAME_LEN+6] = ifdata[lindex]['mac']
                    pktbuff[plen - 1] = lindex

                    csock.sendall(pktbuff, 0)
                    print("IS-IS SEND To Java Client: [%d], aclen [%d]" % (zn, plen))

        elif protocol_flag == 0:
            while loop:
                zn, iinfo = rawsock.recvfrom_into(pktbuff, ETH_FRAME_LEN, 0)

                if iinfo[2] == PACKET_OUTGOING:
                    continue

                if pktbuff[12] == 0x08 and pktbuff[13] == 0x00 and pktbuff[23] == 0x59:
                    ip_header_length = ((pktbuff[14] & 0x0F) << 2) + 14
                    plen = 1521 - ip_header_length
                    pktbuff[ETH_FRAME_LEN + 2] = if_nametoindex(iinfo[0])
                    pktbuff[ETH_FRAME_LEN + 3:ETH_FRAME_LEN + 7] = pktbuff[26:30]
                    csock.sendall(pktbuff[ip_header_length:], 0)
                    print("OSPF SEND To Java Client: [%d], aclen [%d]" % (plen, zn))

    except InterruptedError:
        pass

recvbuff = bytearray(ETH_FRAME_LEN + 1)

try:
    rawsock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
    rawsock.setsockopt(SOL_SOCKET, SO_ATTACH_FILTER, packdata)

    sock = socket(AF_INET, SOCK_STREAM)
    sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    sock.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)
    sock.bind((SHOST, SPORT))
    sock.listen(5)

    csock, null = sock.accept()

    if protocol_flag:
        recvbuff[12:17] = (0x05, 0xDC, 0xFE, 0xFE, 0x03)
    else:
        ospf_wsock = socket(AF_INET, SOCK_RAW, 0x59)

    wthread = threading.Thread(target=thread_callback)
    wthread.start()

    while loop:
        rplen = 0

        while rplen != 1498:
            nbytes = csock.recv(1498 - rplen, 0)
            recvbuff[17 + rplen:] = nbytes

            if (len(nbytes) == 0):
                print("socket Error [from java client]", file=stderr)

                if wthread:
                    pthread_kill(wthread.ident, SIGALRM)

                raise EOFError

            rplen += len(nbytes)

        print("RECEIVED FROM Java Client: [%d]" % rplen)

        if recvbuff[17] == ISIS_CONFIG_PACKET_TYPE:
            nifentry = recvbuff[18] # no of interface entry
            istart = 19

            while nifentry:
                tindex = recvbuff[istart]
                rtype = ifdata[tindex].get('type', -1) ## router type

                if rtype == L1NL2:
                    mreq = pack('iHH6B2x', tindex, PACKET_MR_MULTICAST, ETH_A_LEN, *mtuple[L1])
                    rawsock.setsockopt(SOL_PACKET, PACKET_DROP_MEMBERSHIP, mreq)

                    mreq = pack('iHH6B2x', tindex, PACKET_MR_MULTICAST, ETH_A_LEN, *mtuple[L2])
                    rawsock.setsockopt(SOL_PACKET, PACKET_DROP_MEMBERSHIP, mreq)

                elif rtype >= L1 and rtype <= P2P:
                    mreq = pack('iHH6B2x', tindex, PACKET_MR_MULTICAST, ETH_A_LEN, *mtuple[rtype])
                    rawsock.setsockopt(SOL_PACKET, PACKET_DROP_MEMBERSHIP, mreq)

                rtype = recvbuff[istart + 1]
                ifdata[tindex]['type'] = rtype

                if rtype == L1NL2:
                    mreq = pack('iHH6B2x', tindex, PACKET_MR_MULTICAST, ETH_A_LEN, *mtuple[L1])
                    rawsock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)

                    mreq = pack('iHH6B2x', tindex, PACKET_MR_MULTICAST, ETH_A_LEN, *mtuple[L2])
                    rawsock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
                else:
                    mreq = pack('iHH6B2x', tindex, PACKET_MR_MULTICAST, ETH_A_LEN, *mtuple[rtype])
                    rawsock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)

                istart += 2
                nifentry -= 1
            # done with ISIS/OSPF configuration #
            if protocol_flag == 0:
                loop = False

            continue

        pdu_length = int.from_bytes(recvbuff[(17 + recvbuff[23]):(recvbuff[23] + 19)], byteorder='big', signed=False)
        recvbuff[12:14] = (pdu_length + 3).to_bytes(2, byteorder='big', signed=False)
        recvbuff[23] = 0

        tindex = recvbuff[ETH_FRAME_LEN]

        recvbuff[6:12] = ifdata[tindex]['mac'] # source mac address

        if (ifdata[tindex]['type'] == L1NL2):
            tindex = L2

            if recvbuff[21] == L1_LAN or recvbuff[21] == L1_LSP or recvbuff[21] == L1_CSNP or recvbuff[21] == L1_PSNP:
                tindex = L1
            recvbuff[0:6] = mtuple[tindex] # destination Multicast address
        else:
            recvbuff[0:6] = mtuple[ifdata[tindex]['type']] # destination Multicast address

        tindex = recvbuff[ETH_FRAME_LEN]

        nbytes = rawsock.sendto(recvbuff[:17 + pdu_length], 0, (ifdata[tindex]['if_name'], 0))
        print("IS-IS SEND: [%d], Interface Index %d" % (nbytes, tindex))

    if protocol_flag == 0:
        loop = True

        while loop:
            rplen = 0

            while rplen != 16:
                nbytes = csock.recv(16 - rplen, 0)
                recvbuff[rplen:] = nbytes

                if len(nbytes) == 0:
                    print("socket Error [from java client]", file=stderr)

                    if wthread:
                        pthread_kill(wthread.ident, SIGALRM)

                    raise EOFError

                rplen += len(nbytes)

            rplen = 0

            pdu_length = int.from_bytes(recvbuff[2:4], byteorder='big', signed=False)

            while rplen != (pdu_length - 10):
                nbytes = csock.recv(pdu_length - 10 - rplen, 0)
                recvbuff[(16 + rplen):] = nbytes

                if len(nbytes) == 0:
                    print("socket Error [from java client]", file=stderr)

                    if wthread:
                        pthread_kill(wthread.ident, SIGALRM)

                    raise EOFError

                rplen += len(nbytes)

            print("OSPF RECEIVED FROM Java Client: [%d]" % (pdu_length + 6))

            ospf_wsock.bind((ifdata[recvbuff[pdu_length]]['if_name'], 0)) # bind to interface

            iaddr = inet_ntoa(bytes(recvbuff[(pdu_length + 2):(pdu_length + 6)]))
            nbytes = ospf_wsock.sendto(recvbuff[:pdu_length], 0, (iaddr, 0))
            ospf_wsock.bind(("", 0))
            print("OSPF SEND: [%d], Interface Index %d" % (pdu_length, recvbuff[pdu_length]))

except EOFError:
    for sel in (csock, sock, rawsock, ospf_wsock):
        if sel:
            sel.close()
    execlp("python3", "python3", argv[0], argv[1])

except KeyboardInterrupt:
    if wthread:
        pthread_kill(wthread.ident, SIGALRM)
