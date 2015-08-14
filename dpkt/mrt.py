# $Id: mrt.py 29 2007-01-26 02:29:07Z jon.oberheide $
# -*- coding: utf-8 -*-
"""Multi-threaded Routing Toolkit."""

import dpkt
import bgp
import struct

# Multi-threaded Routing Toolkit
# http://www.ietf.org/internet-drafts/draft-ietf-grow-mrt-03.txt

# MRT Types
NULL = 0
START = 1
DIE = 2
I_AM_DEAD = 3
PEER_DOWN = 4
BGP = 5  # Deprecated by BGP4MP
RIP = 6
IDRP = 7
RIPNG = 8
BGP4PLUS = 9  # Deprecated by BGP4MP
BGP4PLUS_01 = 10  # Deprecated by BGP4MP
OSPF = 11
TABLE_DUMP = 12
TABLE_DUMP_V2 = 13
BGP4MP = 16
BGP4MP_ET = 17
ISIS = 32
ISIS_ET = 33
OSPFv3 = 48
OSPFv3_ET = 49
OSPF_ET = 64

# BGP4MP Subtypes
BGP4MP_STATE_CHANGE = 0
BGP4MP_MESSAGE = 1
BGP4MP_ENTRY = 2
BGP4MP_SNAPSHOT = 3
BGP4MP_MESSAGE_32BIT_AS = 4

# Address Family Types
AFI_IPv4 = 1
AFI_IPv6 = 2

# TABLE_DUMP_V2 Subtypes
PEER_INDEX_TABLE = 1
RIB_IPV4_UNICAST = 2
RIB_IPV4_MULTICAST = 3
RIB_IPV6_UNICAST = 4
RIB_IPV6_MULTICAST = 5
RIB_GENERIC = 6

class MRTHeader(dpkt.Packet):
    __hdr__ = (
        ('ts', 'I', 0),
        ('type', 'H', 0),
        ('subtype', 'H', 0),
        ('len', 'I', 0)
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)

class TableDump(dpkt.Packet):
    __hdr__ = (
        ('view', 'H', 0),
        ('seq', 'H', 0),
        ('prefix', 'I', 0),
        ('prefix_len', 'B', 0),
        ('status', 'B', 1),
        ('originated_ts', 'I', 0),
        ('peer_ip', 'I', 0),
        ('peer_as', 'H', 0),
        ('attr_len', 'H', 0)
    )

    def __init__(self, *arg, **kwargs):
        super(TableDump, self).__init__(arg, kwargs)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        plen = self.attr_len
        l = []
        while plen > 0:
            attr = bgp.BGP.Update.Attribute(self.data)
            self.data = self.data[len(attr):]
            plen -= len(attr)
            l.append(attr)
        self.data = self.attributes = l

    def __str__(self):
        return self.pack_hdr() + struct.pack('>H', sum(map(len, self.attributes))) + \
               ''.join(map(str, self.attributes))

class TableDumpV2(dpkt.Packet):
    __hdr__ = (
        ('seq', 'I', 0),
        ('prefix_len', 'B', 0),
        # ('prefix', 'I', 0),
        # ('entry_count', 'H', 0)
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.prefix_len = (self.prefix_len + 7) / 8
        tmp = self.data[:self.prefix_len]
        tmp += (4 - len(tmp)) * '\x00'
        self.prefix = tmp
        self.data = self.data[self.prefix_len:]
        self.entry_count = struct.unpack('>H', self.data[:2])[0]
        self.data = self.data[2:]
        e = []
        for _ in range(self.entry_count):
            entry = self.RIBIPv4(self.data)
            e.append(entry)
            self.data = self.data[len(entry):]
        self.data = self.entries = e
    def __len__(self):
        return self.__hdr_len__ + sum(map(len, self.entries))

    # class PeerIndexTable(dpkt.Packet):
    #     __hdr__ = (
    #         ('collector_bgp_id', 'I', 0),
    #         ('view_name_len', 'H', 0),
    #         # ('view_name', 's', 0),
    #         # ('peer_count', 'H', 0),
    #     )
    #     def unpack(self, buf):
    #         dpkt.Packet.unpack(self, buf)
    #         self.view_name = self.data[:self.view_name_len]
    #         self.data = self.data[self.view_name_len]
    #         self.peer_count = struct.unpack('>H', self.data[:2])
    #         self.data = self.data[2:]
    #         peers = []
    #         plen = self.peer_count
    #         while plen > 0:
    #             peer = self.PeerEntry(self.data)
    #             self.data = self.data[len(peer):]
    #             plen -= len(peer)
    #             peers.append(peer)
    #         self.peers = peers
    #     def __len__(self):
    #         return self.__hdr_len__ + \
    #             2 + len(self.view_name) + \
    #             2 + sum(map(len, self.peers))

    #     class PeerEntry(dpkt.Packet):
    #         pass

    class RIBIPv4(dpkt.Packet):
        __hdr__ = (
            ('peer', 'H', 0),
            ('orig_ts', 'I', 0),
            ('attr_len', 'H', 0),
        )

        def unpack(self, buf):
            dpkt.Packet.unpack(self, buf)
            plen = self.attr_len
            l = []
            while plen > 0:
                attr = bgp.BGP.Update.Attribute(self.data)
                self.data = self.data[len(attr):]
                plen -= len(attr)
                l.append(attr)
            self.attributes = l

        def __len__(self):
            return self.__hdr_len__ + sum(map(len, self.attributes))

class BGP4MPMessage(dpkt.Packet):
    __hdr__ = (
        ('src_as', 'H', 0),
        ('dst_as', 'H', 0),
        ('intf', 'H', 0),
        ('family', 'H', AFI_IPv4),
        ('src_ip', 'I', 0),
        ('dst_ip', 'I', 0)
    )


class BGP4MPMessage_32(dpkt.Packet):
    __hdr__ = (
        ('src_as', 'I', 0),
        ('dst_as', 'I', 0),
        ('intf', 'H', 0),
        ('family', 'H', AFI_IPv4),
        ('src_ip', 'I', 0),
        ('dst_ip', 'I', 0)
    )
