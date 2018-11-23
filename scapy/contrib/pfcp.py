# coding=utf-8
# ! /usr/bin/env python

# Copyright (C) 2018 Leonardo Monteiro <decastromonteiro@gmail.com>
#
#
# This program is published under a GPLv2 license

# scapy.contrib.description = Packet Forwarding Control Protocol (PFCP)
# scapy.contrib.status = loads

from __future__ import absolute_import
import struct
from scapy.fields import BitEnumField, BitField, ByteEnumField, ByteField, \
    ConditionalField, IntField, IPField, ShortField, StrLenField, ShortEnumField

from scapy.layers.inet6 import IP6Field
from scapy.packet import Packet, plain_str, bytes_hex
from scapy.volatile import RandIP, RandIP6


def pfcp():
    """
    3GPP TS 29.244 Rel 15.3.0 (2018-19)
    Packet Forwarding Control Protocol (PFCP) is used on the interface between the control plane
    and the user plane function.
    PFCP shall be used over:
    -> the Sxa, Sxb, Sxc and the combined Sxa/Sxb reference points specified in 3GPP TS 23.214.
    -> the Sxa' and Sxb' reference points specified in 3GPP TS 33.107
    -> the N4 interface specified in 3GPP TS 23.501 and 3GPP TS 23.502

    The PFCP Protocol Stack for Control Plane is depicted in the picture below:

                               PFCP Protocol Stack

                    ###########         |           ############
                    ##  PFCP ##   ------|-------    ##  PFCP  ##
                    ###########         |           ############
                                        |
                    ###########         |           ############
                    ##   UDP ##   ------|-------    ##   UDP  ##
                    ###########         |           ############
                                        |
                    ###########         |           ############
                    ##   IP  ##   ------|-------    ##   IP   ##
                    ###########         |           ############
                                        |
                    ###########         |           ############
                    ##   L2  ##   ------|-------    ##   L2   ##
                    ###########         |           ############
                                        |
                    ###########         |           ############
                    ##   L1  ##   ------|-------    ##   L1   ##
                    ###########         |           ############
                                        |
                   CP Function  Interface Sx / N4    UP Function

    The PFCP Protocol Stack for User Plane is depicted in the picture below:

                               PFCP Protocol Stack

                    ###########         |           ############
                    ## GTP-U ##   ------|-------    ##  GTP-U ##
                    ###########         |           ############
                                        |
                    ###########         |           ############
                    ##   UDP ##   ------|-------    ##   UDP  ##
                    ###########         |           ############
                                        |
                    ###########         |           ############
                    ##   IP  ##   ------|-------    ##   IP   ##
                    ###########         |           ############
                                        |
                    ###########         |           ############
                    ##   L2  ##   ------|-------    ##   L2   ##
                    ###########         |           ############
                                        |
                    ###########         |           ############
                    ##   L1  ##   ------|-------    ##   L1   ##
                    ###########         |           ############
                                        |
                   CP Function  Interface Sx / N4    UP Function

    The UDP Destination Port number for a Request message shall be 8805.
    The UDP Source Port for a Request message is a locally allocated port number at the sending entity.

    """


class IE_Base(Packet):
    """
    If the Bit 8 of Octet 1 is not set, this indicates that the IE is defined by 3GPP and the Enterprise ID is absent.
    If Bit 8 of Octet 1 is set, this indicates that the IE is defined by a vendor and the Enterprise ID is present
    identified by the Enterprise ID.

    An IE has the following mandatory fields:

    -	Type: this field indicates the type of the Information Element. IE type values within the range of
    0 to 32767 are reserved for IE defined by 3GPP and are listed in subclause 8.1.2 IE type values within the range
    of 32768 to 65535 are used for vendor-specific IE and the value allocation is controlled by the vendor.

    -	Length: this field contains the length of the IE excluding the first four octets, which are common for all
    IEs (Type and Length) and is denoted "n" in Figure 8.1.1-1 and in Figure 8.1.1-2. Bit 8 of the lowest numbered octet
     is the most significant bit and bit 1 of the highest numbered octet is the least significant bit.


    An IE has the following optional fields:

    -	Enterprise ID: if the IE type value is within the range of 32768 to 65535, this field shall contain
    the IANA-assigned "SMI Network Management Private Enterprise Codes" value of the vendor defining the IE.
    The Enterprise ID set to "10415" (IANA-assigned "SMI Network Management Private Enterprise Codes")
    shall not be used for the vendor specific IEs.

    Information Element Format:

    Octets          8     7       6       5       4       3       2       1
    1 to 2        #                     Type = xxx (decimal)                #
    3 to 4        #                     Length = n                          #
   p to (p+1)     #                     Enterprise ID                       #
   k to (n+4)     #         IE specific data or content of a grouped IE     #

    """
    name = "IE Base"
    ie_types = {0: "Reserved",
                1: "Create PDR",
                2: "PDI",
                3: "Create FAR",
                4: "Forwarding Parameters",
                5: "Duplicating Parameters",
                6: "Create URR",
                7: "Create QER",
                8: "Created PDR",
                9: "Update PDR",
                10: "Update FAR",
                11: "Update Forwarding Parameters",
                12: "Update BAR (PFCP Session Report Response)",
                13: "Update URR",
                14: "Update QER",
                15: "Remove PDR",
                16: "Remove FAR",
                17: "Remove URR",
                18: "Remove QER",
                19: "Cause",
                20: "Source Interface",
                21: "F-TEID",
                22: "Network Instance",
                23: "SDF Filter",
                24: "Application ID",
                25: "Gate Status",
                26: "MBR",
                27: "GBR",
                28: "QER Correlation ID",
                29: "Precedence",
                30: "Transport Level Marking",
                31: "Volume Threshold",
                32: "Time Threshold",
                33: "Monitoring Time",
                34: "Subsequent Volume Threshold",
                35: "Subsequent Time Threshold",
                36: "Inactivity Detection Time",
                37: "Reporting Triggers",
                38: "Redirect Information",
                39: "Report Type",
                40: "Offending IE",
                41: "Forwarding Policy",
                42: "Destination Interface",
                43: "UP Function Features",
                44: "Apply Action",
                45: "Downlink Data Service Information",
                46: "Downlink Data Notification Delay",
                47: "DL Buffering Duration",
                48: "DL Buffering Suggested Packet Count",
                49: "PFCPSMReq-Flags",
                50: "PFCPSRRsp-Flags",
                51: "Load Control Information",
                52: "Sequence Number",
                53: "Metric",
                54: "Overload Control Information",
                55: "Timer",
                56: "Packet Detection Rule ID",
                57: "F-SEID",
                58: "Application ID's PFDs",
                59: "PFD context",
                60: "Node ID",
                61: "PFD contents",
                62: "Measurement Method",
                63: "Usage Report Trigger",
                64: "Measurement Period",
                65: "FQ-CSID",
                66: "Volume Measurement",
                67: "Duration Measurement",
                68: "Application Detection Information",
                69: "Time of First Packet",
                70: "Time of Last Packet",
                71: "Quota Holding Time",
                72: "Dropped DL Traffic Threshold",
                73: "Volume Quota",
                74: "Time Quota",
                75: "Start Time",
                76: "End Time",
                77: "Query URR",
                78: "Usage Report (in Session Modification Response)",
                79: "Usage Report (Session Deletion Response)",
                80: "Usage Report (Session Report Request)",
                81: "URR ID",
                82: "Linked URR ID",
                83: "Downlink Data Report",
                84: "Outer Header Creation",
                85: "Create BAR",
                86: "Update BAR (Session Modification Request)",
                87: "Remove BAR",
                88: "BAR ID",
                89: "CP Function Features",
                90: "Usage Information",
                91: "Application Instance ID",
                92: "Flow Information",
                93: "UE IP Address",
                94: "Packet Rate",
                95: "Outer Header Removal",
                96: "Recovery Time Stamp",
                97: "DL Flow Level Marking",
                98: "Header Enrichment",
                99: "Error Indication Report",
                100: "Measurement Information",
                101: "Node Report Type",
                102: "User Plane Path Failure Report",
                103: "Remote GTP-U Peer",
                104: "UR-SEQN",
                105: "Update Duplicating Parameters",
                106: "Activate Predefined Rules",
                107: "Deactivate Predefined Rules",
                108: "FAR ID",
                109: "QER ID",
                110: "OCI Flags",
                111: "PFCP Association Release Request",
                112: "Graceful Release Period",
                113: "PDN Type",
                114: "Failed Rule ID",
                115: "Time Quota Mechanism",
                116: "User Plane IP Resource Information",
                117: "User Plane Inactivity Timer",
                118: "Aggregated URRs",
                119: "Multiplier",
                120: "Aggregated URR ID",
                121: "Subsequent Volume Quota",
                122: "Subsequent Time Quota",
                123: "RQI",
                124: "QFI",
                125: "Query URR Reference",
                126: "Additional Usage Reports Information",
                127: "Create Traffic Endpoint",
                128: "Created Traffic Endpoint",
                129: "Update Traffic Endpoint",
                130: "Remove Traffic Endpoint",
                131: "Traffic Endpoint ID",
                132: "Ethernet Packet Filter",
                133: "MAC address",
                134: "C-TAG",
                135: "S-TAG",
                136: "Ethertype",
                137: "Proxying",
                138: "Ethernet Filter ID",
                139: "Ethernet Filter Properties",
                140: "Suggested Buffering Packets Count",
                141: "User ID",
                142: "Ethernet PDU Session Information",
                143: "Ethernet Traffic Information",
                144: "MAC Addresses Detected",
                145: "MAC Addresses Removed",
                146: "Ethernet Inactivity Timer",
                147: "Additional Monitoring Time",
                148: "Event Information",
                149: "Event Reporting",
                150: "Event ID",
                151: "Event Threshold",
                152: "Trace Information",
                153: "Framed-Route",
                154: "Framed-Routing",
                155: "Framed-IPv6-Route"}
    fields_desc = [ShortEnumField("type", 0, ie_types),
                   ShortField("length", None)]

    def post_build(self, pkt, pay):
        """
        This post build is here to calculate the length field in an Information Element.
        According to 3GPP TS 29.244 this field contains the length of the IE excluding the first four octets, which are
        the type and length field.

        In order to achieve this:
         1 - First concatenate packet and payload bytestrings.
         2 - Calculate the entire length of the packet and exclude 4
         3 - The final packet must be assembled again concatenating the following fields:
            a - type field
            b - calculated length field
            c - the rest of the packet

        :param pkt: packet in bytestring format
        :param pay: payload of the packet in bytestring format
        :return: packet in bytestring format
        """

        pkt += pay
        if self.length is None:
            length = len(pkt) - 4
            # noinspection PyTypeChecker
            pkt = pkt[:2] + struct.pack('!H', length) + pkt[4:]
        return pkt

    def extract_padding(self, pkt):
        return "", pkt


class IE_Cause(IE_Base):
    """
    The Cause value shall be included in a response message.

    In a response message, the Cause value indicates the acceptance or the rejection of
    the corresponding request message.

    The Cause value indicates the explicit reason for the rejection.
    """
    name = "Cause"
    cause_values = {0: "Reserved",
                    1: "Request accepted (success)",
                    64: "Request rejected (reason not specified)",
                    65: "Session context not found",
                    66: "Mandatory IE missing",
                    67: "Conditional IE missing",
                    68: "Invalid length",
                    69: "Mandatory IE incorrect",
                    70: "Invalid Forwarding Policy",
                    71: "Invalid F-TEID allocation option",
                    72: "No established PFCP Association",
                    73: "Rule creation/modification Failure",
                    74: "PFCP entity in congestion",
                    75: "No resources available",
                    76: "Service not supported",
                    77: "System failure"}
    fields_desc = [ShortEnumField("type", 19, IE_Base.ie_types),
                   ShortField("length", None),
                   ByteEnumField("cause_value", 1, cause_values)]


class IE_SourceInterface(IE_Base):
    """
    It indicates the type of the interface from which an incoming packet is received.
    NOTE: The "Access" and "Core" values denote an uplink and downlink traffic direction respectively.
    """
    name = "Source Interface"
    interface_values = {0: "Access",
                        1: "Core",
                        2: "SGi-LAN/N6-LAN",
                        3: "CP-function",
                        4: "Spare",
                        5: "Spare",
                        6: "Spare",
                        7: "Spare",
                        8: "Spare",
                        9: "Spare",
                        10: "Spare",
                        11: "Spare",
                        12: "Spare",
                        13: "Spare",
                        14: "Spare",
                        15: "Spare"}
    fields_desc = [ShortEnumField("type", 20, IE_Base.ie_types),
                   ShortField("length", None),
                   BitField("spare", 0, 4),
                   BitEnumField("interface_value", 1, 4, interface_values)]


class IE_FTEID(IE_Base):
    """
    It indicates an Fully Qualified Tunnel Endpoint Identification

    """
    name = "F-TEID"
    fields_desc = [ShortEnumField("type", 21, IE_Base.ie_types),
                   ShortField("length", None),
                   BitField("spare", 0, 4),
                   BitField("chid", 0, 1),
                   BitField("ch", 0, 1),
                   BitField("v6", 1, 1),
                   BitField("v4", 1, 1),
                   ConditionalField(IntField('teid', 0),
                                    lambda pkt: pkt.ch == 0),
                   ConditionalField(IPField("ipv4_address", RandIP()),
                                    lambda pkt: pkt.v4 == 1 and pkt.ch == 0),
                   ConditionalField(IP6Field("ipv6_address", RandIP6()),
                                    lambda pkt: pkt.v6 == 1 and pkt.ch == 0),
                   ConditionalField(ByteField("choose_id", 0),
                                    lambda pkt: pkt.chid == 1)]


class OctetString(StrLenField):
    """
    Copied from scapy.contrib.diameter
    """

    def i2repr(self, pkt, x):
        try:
            return plain_str(x)
        except BaseException:
            return bytes_hex(x)


class IE_NetworkInstance(IE_Base):
    """
    The Network instance field shall be encoded as an OctetString and shall contain an identifier which
    uniquely identifies a particular Network instance (e.g. PDN instance) in the UP function.
    It may be encoded as a Domain Name or an Access Point Name (APN) as per subclause 9.1 of 3GPP TS 23.003.
    In the latter case, the PDN Instance field may contain the APN Network Identifier only or the full APN with
    both the APN Network Identifier and the APN Operator Identifier as specified in 3GPP TS 23.003.

    NOTE:	The APN field is not encoded as a dotted string as commonly used in documentation.

    """
    name = "Network Instance"
    fields_desc = [ShortEnumField("type", 22, IE_Base.ie_types),
                   ShortField("length", None),
                   OctetString("network_instance", "internet", length_from=lambda pkt: len(pkt.network_instance))]


class IE_SDFFilter(IE_Base):
    # todo: create a Field Class to support an octetstring with user defined size ex:tos_traffic_class, security, etc..
    name = "SDF Filter"
    fields_desc = [ShortEnumField("type", 23, IE_Base.ie_types),
                   ShortField("length", None),
                   BitField("spare", 0, 3),
                   BitField("bid", 0, 1),
                   BitField("fl", 0, 1),
                   BitField("spi", 0, 1),
                   BitField("ttc", 0, 1),
                   BitField("fd", 0, 1),
                   ByteField("second_spare", 0),
                   ShortField("fld_length", None),
                   OctetString("flow_description", "whatsapp", length_from=lambda pkt: len(pkt.flow_description)),
                   ShortField("tos_traffic_class", 0),
                   ]


class IE_ApplicationID(IE_Base):
    """
    It contains an Application Identifier referencing an application detection filter in the UP function
    (e.g. its value may represent an application such as a list of URLs).
    """
    name = "Application ID"
    fields_desc = [ShortEnumField("type", 24, IE_Base.ie_types),
                   ShortField("length", None),
                   OctetString("application_identifier", "www.google.com",
                               length_from=lambda pkt: len(pkt.application_identifier))]


class IE_GateStatus(IE_Base):
    """
    It indicates whether the service data flow or application's traffic is allowed to be forwarded (gate is open)
    or shall be discarded (gate is closed) in uplink and/or in downlink direction.
    """
    gate_values = {0: 'OPEN',
                   1: 'CLOSED',
                   2: 'For Future Use (CLOSED)',
                   3: 'For Future Use (CLOSED)'}
    name = "Gate Status"
    fields_desc = [ShortEnumField("type", 25, IE_Base.ie_types),
                   ShortField("length", None),
                   BitField("spare", 0, 4),
                   BitEnumField("ul_gate", 0, 2, gate_values),
                   BitEnumField("dl_gate", 0, 2, gate_values)]


class PFCPHeader(Packet):
    PFCPmessageType = {
        0: "Reserved",
        #   PFCP Node related messages
        1: "PFCP Heartbeat Request",
        2: "PFCP Heartbeat Response",
        3: "PFCP PFD Management Request",
        4: "PFCP PFD Management Response",
        5: "PFCP Association Setup Request",
        6: "PFCP Association Setup Response",
        7: "PFCP Association Update Request",
        8: "PFCP Association Update Response",
        9: "PFCP Association Release Request",
        10: "PFCP Association Release Response",
        11: "PFCP Version Not Supported Response",
        12: "PFCP Node Report Request",
        13: "PFCP Node Report Response",
        14: "PFCP Session Set Deletion Request",
        15: "PFCP Session Set Deletion Response",
        #    PFCP Session related messages
        50: "PFCP Session Establishment Request",
        51: "PFCP Session Establishment Response",
        52: "PFCP Session Modification Request",
        53: "PFCP Session Modification Response",
        54: "PFCP Session Deletion Request",
        55: "PFCP Session Deletion Response",
        56: "PFCP Session Report Request",
        57: "PFCP Session Report Response"
    }

    name = "PFCP Header"
    fields_desc = []
