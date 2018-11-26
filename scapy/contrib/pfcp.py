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
    ConditionalField, IntField, IPField, ShortField, StrLenField, ShortEnumField, \
    LongField, SecondsIntField, UTCTimeField, FieldLenField, XBitField, PacketListField, \
    BoundStrLenField, Field

from scapy.layers.inet import UDP
from scapy.layers.inet6 import IP6Field
from scapy.packet import Packet, plain_str, bytes_hex, bind_layers, Raw
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
    fields_desc = [ShortEnumField("ietype", 0, ie_types),
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


class IE_NotImplemented(IE_Base):
    """
    Inspired by scapy.contrib.gtp
    """
    name = "IE Not Implemented"
    fields_desc = [ShortEnumField("ietype", 0, IE_Base.ie_types),
                   ShortField("length", None),
                   ConditionalField(ShortField('enterprise_id', 2202),
                                    lambda pkt: pkt.ietype >= 32768),
                   StrLenField("data", "", length_from=lambda x: x.length)]

    def extract_padding(self, pkt):
        return "", pkt


def IE_Dispatcher(pkt):
    """
    Inspired by scapy.contrib.gtp
    Function to be passed to PacketListField parameter cls.
    This function works as a dispatch_hook classmethod.
    This function will try to identify the correct Information Elements that are in the PacketListField.
    """
    # Define a dictionary of Information Elements Classes identified by ietype.
    ietype_cls = {19: IE_Cause,
                  20: IE_SourceInterface,
                  21: IE_FTEID,
                  22: IE_NetworkInstance,
                  23: IE_SDFFilter,
                  24: IE_ApplicationID,
                  25: IE_GateStatus,
                  28: IE_QERCorrelationID,
                  29: IE_Precedence,
                  31: IE_VolumeThreshold,
                  32: IE_TimeThreshold,
                  33: IE_MonitoringTime,
                  34: IE_SubsequentVolumeThreshold,
                  35: IE_SubsequentTimeThreshold,
                  36: IE_InactivityDetectionTime,
                  37: IE_ReportingTriggers,
                  38: IE_RedirectInformation,
                  39: IE_ReportType,
                  40: IE_OffendingIE,
                  42: IE_DestinationInterface,
                  43: IE_UPFunctionFeatures,
                  44: IE_ApplyAction,
                  58: IE_ApplicationIDsPFDs,
                  59: IE_PFD,
                  61: IE_PFDContents,
                  96: IE_RecoveryTimeStamp,
                  }
    # If packet length is less than 2, we cannot extract the "length" field, so return Raw()
    if len(pkt) < 2:
        return Raw(pkt)
    # Try to use struct.unpack to solve the ietype field and convert it to decimal.
    try:
        ietype = struct.unpack("!H", pkt[:2])[0]
        cls = ietype_cls.get(ietype, IE_NotImplemented)
        return cls(pkt)
    # If there is a struct.error exception, return the Raw packet string.
    except struct.error:
        return Raw(pkt)


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
    fields_desc = [ShortEnumField("ietype", 19, IE_Base.ie_types),
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
    fields_desc = [ShortEnumField("ietype", 20, IE_Base.ie_types),
                   ShortField("length", None),
                   BitField("spare", 0, 4),
                   BitEnumField("interface_value", 1, 4, interface_values)]


class IE_FTEID(IE_Base):
    """
    It indicates an Fully Qualified Tunnel Endpoint Identification

    """
    name = "F-TEID"
    fields_desc = [ShortEnumField("ietype", 21, IE_Base.ie_types),
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


class BoundOctetStrLenField(BoundStrLenField):
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
    fields_desc = [ShortEnumField("ietype", 22, IE_Base.ie_types),
                   ShortField("length", None),
                   OctetString("network_instance", "internet", length_from=lambda pkt: len(pkt.network_instance))]


class IE_SDFFilter(IE_Base):
    # todo: revisit this SDFFilter to check how to proceed with maxlen on OctetString
    name = "SDF Filter"
    fields_desc = [ShortEnumField("ietype", 23, IE_Base.ie_types),
                   ShortField("length", None),
                   BitField("spare", 0, 3),
                   BitField("bid", 0, 1),
                   BitField("fl", 0, 1),
                   BitField("spi", 0, 1),
                   BitField("ttc", 0, 1),
                   BitField("fd", 0, 1),
                   ByteField("second_spare", 0),
                   ConditionalField(FieldLenField("fld_length", None, length_of="flow_description"),
                                    lambda pkt: pkt.fd == 1),
                   ConditionalField(OctetString("flow_description", "whatsapp",
                                                length_from=lambda pkt: pkt.fld_length),
                                    lambda pkt: pkt.fd == 1),
                   ConditionalField(BoundOctetStrLenField("tos_traffic_class", "", maxlen=2,
                                                          length_from=lambda pkt: len(pkt.tos_traffic_class)),
                                    lambda pkt: pkt.ttc == 1),
                   ConditionalField(BoundOctetStrLenField("security_param_idx", "", maxlen=4,
                                                          length_from=lambda pkt: len(pkt.security_param_idx)),
                                    lambda pkt: pkt.spi == 1),
                   ConditionalField(BoundOctetStrLenField("flow_label", "google_dns", maxlen=3,
                                                          length_from=lambda pkt: len(pkt.flow_label)),
                                    lambda pkt: pkt.fl == 1),
                   ConditionalField(IntField("sdf_filter_id", 0),
                                    lambda pkt: pkt.bid == 1)

                   ]


class IE_ApplicationID(IE_Base):
    """
    It contains an Application Identifier referencing an application detection filter in the UP function
    (e.g. its value may represent an application such as a list of URLs).
    """
    name = "Application ID"
    fields_desc = [ShortEnumField("ietype", 24, IE_Base.ie_types),
                   ShortField("length", None),
                   OctetString("application_identifier", "Google",
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
    fields_desc = [ShortEnumField("ietype", 25, IE_Base.ie_types),
                   ShortField("length", None),
                   BitField("spare", 0, 4),
                   BitEnumField("ul_gate", 0, 2, gate_values),
                   BitEnumField("dl_gate", 0, 2, gate_values)]


class IE_QERCorrelationID(IE_Base):
    """
    It contains a QoS Enforcement Rule Correlation ID to correlate QERs from different PFCP sessions.
    The QER Correlation ID shall be dynamically assigned by the CP function and provisioned by the CP function in
    different PFCP sessions to correlate QERs used in these PFCP sessions.
    """
    name = "QER Correlation ID"
    fields_desc = [ShortEnumField("ietype", 28, IE_Base.ie_types),
                   ShortField("length", None),
                   IntField("qer_id", 0)]


class IE_Precedence(IE_Base):
    """
    It defines the relative precedence of a PDR among all the PDRs provisioned within an PFCP session,
    when looking for a PDR matching an incoming packet.
    """
    name = "Precedence"
    fields_desc = [ShortEnumField("ietype", 29, IE_Base.ie_types),
                   ShortField("length", None),
                   IntField("precedence", 0)]


class IE_VolumeThreshold(IE_Base):
    """
    The Volume Threshold IE contains the traffic volume thresholds to be monitored by the UP function.
    """
    name = "Volume Threshold"
    fields_desc = [ShortEnumField("ietype", 31, IE_Base.ie_types),
                   ShortField("length", None),
                   BitField("spare", 0, 5),
                   BitField("dlvol", 0, 1),
                   BitField("ulvol", 0, 1),
                   BitField("tovol", 1, 1),
                   ConditionalField(LongField("total_volume", 10000),
                                    lambda pkt: pkt.tovol == 1),
                   ConditionalField(LongField("uplink_volume", 0),
                                    lambda pkt: pkt.ulvol == 1),
                   ConditionalField(LongField("downlink_volume", 0),
                                    lambda pkt: pkt.dlvol == 1)]


class IE_TimeThreshold(IE_Base):
    """
    The Time Threshold IE contains the traffic duration threshold in seconds to be monitored by the UP function.
    """
    name = "Time Threshold"
    fields_desc = [ShortEnumField("ietype", 32, IE_Base.ie_types),
                   ShortField("length", None),
                   SecondsIntField("time_threshold", 0)]


class IE_MonitoringTime(IE_Base):
    """
    The Monitoring Time IE indicates the time at which the UP function is expected to reapply the thresholds.
    The Monitoring Time field shall indicate the monitoring time in UTC time.
    It shall be encoded in the same format as the first four octets of the 64-bit timestamp format as defined
    in section 6 of IETF RFC 5905
    """
    name = "Monitoring Time"
    fields_desc = [ShortEnumField("ietype", 33, IE_Base.ie_types),
                   ShortField("length", None),
                   UTCTimeField("monitoring_time", 0)]


class IE_SubsequentVolumeThreshold(IE_Base):
    """
    The Subsequent Volume Threshold IE contains the subsequent traffic volume thresholds to be monitored
    by the UP function after the Monitoring Time.
    """
    name = "Subsequent Volume Threshold"
    fields_desc = [ShortEnumField("ietype", 34, IE_Base.ie_types),
                   ShortField("length", None),
                   BitField("spare", 0, 5),
                   BitField("dlvol", 0, 1),
                   BitField("ulvol", 0, 1),
                   BitField("tovol", 1, 1),
                   ConditionalField(LongField("total_volume", 10000),
                                    lambda pkt: pkt.tovol == 1),
                   ConditionalField(LongField("uplink_volume", 0),
                                    lambda pkt: pkt.ulvol == 1),
                   ConditionalField(LongField("downlink_volume", 0),
                                    lambda pkt: pkt.dlvol == 1)]


class IE_SubsequentTimeThreshold(IE_Base):
    """
    The Subsequent Time Threshold IE contains the subsequent traffic duration threshold in second
    to be monitored by the UP function after the Monitoring Time.
    """
    name = "Subsequent Time Threshold"
    fields_desc = [ShortEnumField("ietype", 35, IE_Base.ie_types),
                   ShortField("length", None),
                   SecondsIntField("time_threshold", 0)]


class IE_InactivityDetectionTime(IE_Base):
    """
    The Inactivity Detection Time IE contains the inactivity time period, in seconds,
    to be monitored by the UP function.
    """
    name = "Inactivity Detection Time"
    fields_desc = [ShortEnumField("ietype", 36, IE_Base.ie_types),
                   ShortField("length", None),
                   SecondsIntField("detection_time", 0)]


class IE_ReportingTriggers(IE_Base):
    """
    It indicates the reporting trigger(s) for the UP function to send a report to the CP function.

    PERIO (Periodic Reporting): when set to 1, this indicates a request for periodic reporting.

    VOLTH (Volume Threshold): when set to 1, this indicates a request for reporting when
    the data volume usage reaches a volume threshold.

    TIMTH (Time Threshold): when set to 1, this indicates a request for reporting when
    the time usage reaches a time threshold.

    QUHTI (Quota Holding Time): when set to 1, this indicates a request for reporting when
    no packets have been received for a period exceeding the Quota Holding Time.

    START (Start of Traffic): when set to 1, this indicates a request for reporting when
    detecting the start of an SDF or Application traffic.

    STOPT (Stop of Traffic): when set to 1, this indicates a request for reporting when
    detecting the stop of an SDF or Application Traffic.

    DROTH (Dropped DL Traffic Threshold): when set to 1, this indicates a request for reporting when
    the DL traffic being dropped reaches a threshold.

    LIUSA (Linked Usage Reporting): when set to 1, this indicates a request for linked usage reporting,
    i.e. a request for reporting a usage report for a URR when a usage report is reported for a linked URR

    VOLQU (Volume Quota): when set to 1, this indicates a request for reporting when a Volume Quota is exhausted.

    TIMQU (Time Quota): when set to 1, this indicates a request for reporting when a Time Quota is exhausted.

    ENVCL (Envelope Closure): when set to 1, this indicates a request for reporting when
    conditions for closure of envelope is met.

    MACAR (MAC Addresses Reporting): when set to 1, this indicates a request for reporting the MAC (Ethernet) addresses
    used as source address of frames sent UL by the UE.

    EVETH (Event Threshold): when set to 1, this indicates a request for reporting when an event threshold is reached.

    """
    name = "Reporting Triggers"
    fields_desc = [ShortEnumField("ietype", 37, IE_Base.ie_types),
                   ShortField("length", None),
                   BitField("liusa", 0, 1),
                   BitField("droth", 0, 1),
                   BitField("stopt", 0, 1),
                   BitField("start", 0, 1),
                   BitField("quhti", 0, 1),
                   BitField("timth", 0, 1),
                   BitField("volth", 0, 1),
                   BitField("perio", 0, 1),
                   BitField("spare", 0, 3),
                   BitField("eveth", 0, 1),
                   BitField("macar", 0, 1),
                   BitField("envcl", 0, 1),
                   BitField("timqu", 0, 1),
                   BitField("volqu", 0, 1)]


class StrLenFieldUtf8(StrLenField):
    def h2i(self, pkt, x):
        return plain_str(x).encode('utf-8')

    def i2h(self, pkt, x):
        return x.decode('utf-8')


class IE_RedirectInformation(IE_Base):
    name = "Redirect Information"
    address_types = {0: "IPv4 Address",
                     1: "IPv6 Address",
                     2: "URL",
                     3: "SIP URL",
                     4: "Spare, for future use.",
                     5: "Spare, for future use.",
                     6: "Spare, for future use.",
                     7: "Spare, for future use.",
                     8: "Spare, for future use.",
                     9: "Spare, for future use.",
                     10: "Spare, for future use.",
                     11: "Spare, for future use.",
                     12: "Spare, for future use.",
                     13: "Spare, for future use.",
                     14: "Spare, for future use.",
                     15: "Spare, for future use."}
    fields_desc = [ShortEnumField("ietype", 38, IE_Base.ie_types),
                   ShortField("length", None),
                   BitField("spare", 0, 4),
                   BitEnumField("redirect_address_type", 2, 4, address_types),
                   FieldLenField("redirect_address_length", None, length_of="redirect_server_address"),
                   StrLenFieldUtf8("redirect_server_address", 'www.google.com',
                                   length_from=lambda pkt: pkt.redirect_address_length)]


class IE_ReportType(IE_Base):
    """
    It indicates the type of the report the UP function sends to the CP function.

    DLDR (Downlink Data Report): when set to 1, this indicates Downlink Data Report.

    USAR (Usage Report): when set to 1, this indicates a Usage Report.

    ERIR (Error Indication Report): when set to 1, this indicates an Error Indication Report.

    UPIR (User Plane Inactivity Report): when set to 1, this indicates a User Plane Inactivity Report.

    At least one bit shall be set to 1. Several bits may be set to 1.
    """
    name = "Report Type"
    fields_desc = [ShortEnumField("ietype", 39, IE_Base.ie_types),
                   ShortField("length", None),
                   BitField("spare", 0, 4),
                   BitField("upir", 0, 1),
                   BitField("erir", 0, 1),
                   BitField("usar", 1, 1),
                   BitField("dldr", 0, 1)]


class IE_OffendingIE(IE_Base):
    """
    The offending IE shall contain a mandatory IE type, if the rejection is due to a conditional
    or mandatory IE is faulty or missing.
    """
    name = "Offending IE"
    fields_desc = [ShortEnumField("ietype", 40, IE_Base.ie_types),
                   ShortField("length", None),
                   ShortEnumField("offending_ie_type", 1, IE_Base.ie_types)]


class IE_DestinationInterface(IE_Base):
    """
    It indicates the type of the interface towards which an outgoing packet is sent.
    """
    name = "Destination Interface"
    interface_values = {0: "Access",
                        1: "Core",
                        2: "SGi-LAN/N6-LAN",
                        3: "CP-function",
                        4: "LI Function",
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
    fields_desc = [ShortEnumField("ietype", 42, IE_Base.ie_types),
                   ShortField("length", None),
                   BitField("spare", 0, 4),
                   BitEnumField("interface_value", 0, 4, interface_values)]


class IE_UPFunctionFeatures(IE_Base):
    # todo: Validate what is a bitmask IE and adjust IE accordingly
    """
    The UP Function Features IE indicates the features supported by the UP function

    BUCP Downlink Data Buffering in CP function is supported by the UP function.
    The UP Function Features IE takes the form of a bitmask where each bit set indicates that
    the corresponding feature is supported. Spare bits shall be ignored by the receiver.

    DDND -> The buffering parameter 'Downlink Data Notification Delay' is supported by the UP function.
    DLBD -> The buffering parameter 'DL Buffering Duration' is supported by the UP function.
    TRST -> Traffic Steering is supported by the UP function.
    FTUP -> F-TEID allocation / release in the UP function is supported by the UP function.
    PFDM -> The PFD Management procedure is supported by the UP function.
    HEEU -> Header Enrichment of Uplink traffic is supported by the UP function.
    TREU -> Traffic Redirection Enforcement in the UP function is supported by the UP function.
    EMPU -> Sending of End Marker packets supported by the UP function.
    PDIU -> Support of PDI optimised signalling in UP function (see subclause 5.2.1A.2).
    UDBC -> Support of UL/DL Buffering Control
    QUOAC -> The UP function supports being provisioned with the Quota Action to apply when reaching quotas.
    TRACE -> The UP function supports Trace (see subclause 5.x).
    FRRT -> UP function supports Framed Routing (see IETF RFC 2865 [37] and IETF RFC 3162 [38]).

    """
    name = "UP Function Features"
    fields_desc = [ShortEnumField("ietype", 43, IE_Base.ie_types),
                   ShortField("length", None),
                   BitField("treu", 0, 1),
                   BitField("heeu", 0, 1),
                   BitField("pfdm", 0, 1),
                   BitField("ftup", 0, 1),
                   BitField("trst", 0, 1),
                   BitField("dlbd", 0, 1),
                   BitField("ddnd", 0, 1),
                   BitField("bucp", 0, 1),
                   BitField("spare", 0, 2),
                   BitField("frrt", 0, 1),
                   BitField("trace", 0, 1),
                   BitField("quoac", 0, 1),
                   BitField("udbc", 0, 1),
                   BitField("pdiu", 0, 1),
                   BitField("empu", 0, 1)]


class IE_ApplyAction(IE_Base):
    """
    The Apply Action IE indicates the action(s) the UP function is required to apply to packets.

    DROP (Drop): when set to 1, this indicates a request to drop the packets.
    FORW (Forward): when set to 1, this indicates a request to forward the packets.
    BUFF (Buffer): when set to 1, this indicates a request to buffer the packets.
    NOCP (Notify the CP function): when set to 1, this indicates a request to notify the CP function about
    the arrival of a first downlink packet being buffered.
    DUPL (Duplicate): when set to 1, this indicates a request to duplicate the packets.

    One and only one of the DROP, FORW and BUFF flags shall be set to 1.
    The NOCP flag may only be set if the BUFF flag is set.
    The DUPL flag may be set with any of the DROP, FORW, BUFF and NOCP flags.

    """
    name = "Apply Action"
    fields_desc = [ShortEnumField("ietype", 44, IE_Base.ie_types),
                   ShortField("length", None),
                   BitField("spare", 0, 3),
                   BitField("dupl", 0, 1),
                   BitField("nocp", 0, 1),
                   BitField("buff", 0, 1),
                   BitField("forw", 0, 1),
                   BitField("drop", 0, 1)]


class IE_DownlinkDataServiceInformation(Packet):
    """
    The Downlink Data Service Information IE is used to carry downlink data service information.
    """
    name = "Downlink Data Service Information"
    fields_desc = [ShortEnumField("ietype", 45, IE_Base.ie_types),
                   ShortField("length", None),
                   BitField("spare", 0, 6),
                   BitField("qfii", 0, 1),
                   BitField("ppi", 0, 1),
                   ConditionalField(XBitField("ppi_value_spare", 0, 2), lambda pkt: pkt.ppi == 1),
                   ConditionalField(XBitField("ppi_value", 0, 6), lambda pkt: pkt.ppi == 1),
                   ConditionalField(XBitField("qfi_spare", 0, 2), lambda pkt: pkt.qfii == 1),
                   ConditionalField(XBitField("qfi", 0, 6), lambda pkt: pkt.qfii == 1)
                   ]


class IE_DownlinkDataNotificationDelay(Packet):
    """
    The Downlink Data Notification Delay IE indicates the delay the UP function shall apply between
    receiving a downlink data packet and notifying the CP function about the arrival of the packet.
    """
    name = "Downlink Data Notification Delay"
    fields_desc = [ShortEnumField("ietype", 46, IE_Base.ie_types),
                   ShortField("length", None),
                   ByteField("delay", 0)
                   ]


class IE_DLBufferingDuration(Packet):
    """
    The DL Buffering Duration IE indicates the duration during which the UP function
    is requested to buffer the downlink data packets
    """
    timer_unit_increments = {0: "2 seconds",
                             1: "1 minute",
                             2: "10 minutes",
                             3: "1 hour",
                             4: "10 hours",
                             5: "1 minute",
                             6: "1 minute",
                             7: "Infinite"}
    name = "DL Buffering Duration"
    fields_desc = [ShortEnumField("ietype", 47, IE_Base.ie_types),
                   ShortField("length", None),
                   BitEnumField("timer_unit", 0, 3, timer_unit_increments),
                   BitField("timer_value", 0, 5)
                   ]


class IntLenField(Field):
    """
    IntField with customizable maximum length of octets (bytes).
    maxlen is specified as numbers of octets (bytes).
    """
    __slots__ = ["maxlen", "fmt_dict"]

    def __init__(self, name, default, maxlen=8):
        self.maxlen = maxlen
        self.fmt_dict = {0: '!B', 1: '!B', 2: '!H', 3: "!I", 4: "!I", 5: "!Q", 6: "!Q", 7: "!Q", 8: "!Q"}
        fmt = self.fmt_dict.get(self.maxlen, "!Q")
        Field.__init__(self, name, default, fmt)

    def i2len(self, pkt, i):
        i = int(i)
        bit_length = i.bit_length()
        int_byte_length = int(bit_length / 8)
        float_byte_length = bit_length / 8
        if float_byte_length > int_byte_length:
            if int_byte_length < self.maxlen:
                return int_byte_length + 1
            else:
                return self.maxlen
        if int_byte_length < self.maxlen:
            return int_byte_length
        return self.maxlen

    def i2m(self, pkt, s):
        float_byte_length = int(s).bit_length() / 8
        s = s if float_byte_length <= self.maxlen else (2 ** (self.maxlen * 8) - 1)
        return s

    def addfield(self, pkt, s, val):
        """Add an internal value  to a string"""
        int_byte_length = int(int(val).bit_length() / 8)
        float_byte_length = float(int(val).bit_length() / 8)
        if float_byte_length > int_byte_length:
            if int_byte_length < self.maxlen:
                self.fmt = self.fmt_dict.get(int_byte_length + 1, "!Q")
                return s + struct.pack(self.fmt, self.i2m(pkt, val))
            else:
                self.fmt = self.fmt_dict.get(self.maxlen, "!Q")
                return s + struct.pack(self.fmt, self.i2m(pkt, val))
        self.fmt = self.fmt_dict.get(int_byte_length, "!Q")
        return s + struct.pack(self.fmt, self.i2m(pkt, val))

    def getfield(self, pkt, s):
        """Extract an internal value from a string"""
        self.sz = struct.calcsize(self.fmt)
        return s[self.sz:], self.m2i(pkt, struct.unpack(self.fmt, s[:self.sz])[0])


class IE_DLBufferingSuggestedPacketCount(Packet):
    name = "DL Buffering Suggested Packet Count"
    fields_desc = [ShortEnumField("ietype", 48, IE_Base.ie_types),
                   FieldLenField("length", None, length_of="packet_count"),
                   IntLenField("packet_count", 65535, maxlen=2)
                   ]


class IE_PFDContents(IE_Base):
    """
    FD (Flow Description): If this bit is set to "1", then the Length of Flow Description and
    the Flow Description fields shall be present, otherwise they shall not be present.

    URL (URL): If this bit is set to "1", then the Length of URL and the URL fields shall be present,
    otherwise they shall not be present.

    DN (Domain Name): If this bit is set to "1", then the Length of Domain Name and the Domain Name fields shall
    be present, otherwise they shall not be present.

    CP (Custom PFD Content): If this bit is set to "1", then the Length of Custom PFD Content and
    the Custom PFD Content fields shall be present, otherwise they shall not be present.

    The Flow Description field, when present, shall be encoded as an OctetString.
    The Domain Name field, when present, shall be encoded as an OctetString.
    The URL field, when present, shall be encoded as an OctetString.

    """
    name = "PFD Contents"
    fields_desc = [ShortEnumField("ietype", 61, IE_Base.ie_types),
                   ShortField("length", None),
                   BitField("spare", 0, 4),
                   BitField("cp", 0, 1),
                   BitField("dn", 1, 1),
                   BitField("url", 0, 1),
                   BitField("fd", 0, 1),
                   ConditionalField(FieldLenField("fd_len", None, length_of="flow_description"),
                                    lambda pkt: pkt.fd == 1),
                   ConditionalField(OctetString("flow_description", "from a to b", length_from=lambda pkt: pkt.fd_len),
                                    lambda pkt: pkt.fd == 1),
                   ConditionalField(FieldLenField("url_len", None, length_of="url_str"),
                                    lambda pkt: pkt.url == 1),
                   ConditionalField(OctetString("url_str", "www.google.com", length_from=lambda pkt: pkt.url_len),
                                    lambda pkt: pkt.url == 1),
                   ConditionalField(FieldLenField("dn_len", None, length_of="domain_name"),
                                    lambda pkt: pkt.dn == 1),
                   ConditionalField(OctetString("domain_name", "www.google.com", length_from=lambda pkt: pkt.dn_len),
                                    lambda pkt: pkt.dn == 1),
                   ConditionalField(FieldLenField("cp_len", None, length_of="custom"),
                                    lambda pkt: pkt.cp == 1),
                   ConditionalField(OctetString("custom", "ipv4 to ipv6", length_from=lambda pkt: pkt.cp_len),
                                    lambda pkt: pkt.cp == 1)
                   ]


class IE_PFD(IE_Base):
    """
    Type: Grouped IE
    """
    name = "PFD"
    fields_desc = [ShortEnumField("ietype", 59, IE_Base.ie_types),
                   ShortField("length", None),
                   PacketListField(name='information_elements',
                                   default=[IE_PFDContents()],
                                   cls=IE_Dispatcher)
                   ]


class IE_ApplicationIDsPFDs(IE_Base):
    """
    Type: Grouped IE
    """
    name = "Application ID's PFDs"
    fields_desc = [ShortEnumField("ietype", 58, IE_Base.ie_types),
                   ShortField("length", None),
                   PacketListField(name="information_elements",
                                   default=[IE_ApplicationID(),
                                            IE_PFD()],
                                   cls=IE_Dispatcher)
                   ]


class IE_RecoveryTimeStamp(IE_Base):
    """
    Type: Extendable IE
    It indicates the UTC time when the node started.
    """
    name = "Recovery Time Stamp"
    fields_desc = [ShortEnumField("ietype", 96, IE_Base.ie_types),
                   ShortField("length", None),
                   UTCTimeField("recovery_time", 1543014664)]


#   PFCP Node related messages

class NodePFCPHeader(Packet):
    message_types = {0: "Reserved",
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
                     15: "PFCP Session Set Deletion Response"}

    name = "PFCP Header"
    fields_desc = [BitField("version", 1, 3),
                   BitField("spare", 0, 3),
                   BitField("mp", 0, 1),
                   BitField("s", 0, 1),
                   ByteEnumField("message_type", 0, message_types),
                   ShortField("length", None),
                   ConditionalField(LongField("seid", 0),
                                    lambda pkt: pkt.s == 1),
                   XBitField("sequence", 0, 24),
                   ByteField("_spare", 0)]

    def post_build(self, pkt, pay):
        """
        This post build is here to calculate the length field in an PFCP Header.

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


class PFCPHeartBeatRequest(Packet):
    name = "PFCP Heartbeat Request"
    fields_desc = [PacketListField(name="information_elements",
                                   default=[IE_RecoveryTimeStamp()],
                                   cls=IE_Dispatcher
                                   )
                   ]


class PFCPHeartBeatResponse(Packet):
    name = "PFCP Heartbeat Response"
    fields_desc = [PacketListField(name="information_elements",
                                   default=[IE_RecoveryTimeStamp()],
                                   cls=IE_Dispatcher
                                   )
                   ]


class PFCPPFDManagementRequest(Packet):
    name = "PFCP PFD Management Request"
    fields_desc = [PacketListField(name="information_elements",
                                   default=[IE_ApplicationIDsPFDs()],
                                   cls=IE_Dispatcher
                                   )
                   ]


class PFCPPFDManagementResponse(Packet):
    name = "PFCP PFD Management Response"
    fields_desc = [PacketListField(name="information_elements",
                                   default=[IE_Cause()],
                                   cls=IE_Dispatcher
                                   )
                   ]


bind_layers(UDP, NodePFCPHeader, dport=8805)
bind_layers(UDP, NodePFCPHeader, sport=8805)
bind_layers(NodePFCPHeader, PFCPHeartBeatRequest, message_type=1)
bind_layers(NodePFCPHeader, PFCPHeartBeatResponse, message_type=2)
bind_layers(NodePFCPHeader, PFCPPFDManagementRequest, message_type=3)
bind_layers(NodePFCPHeader, PFCPPFDManagementResponse, message_type=4)


#   PFCP Session related messages

class SessionPFCPHeader(Packet):
    message_types = {50: "PFCP Session Establishment Request",
                     51: "PFCP Session Establishment Response",
                     52: "PFCP Session Modification Request",
                     53: "PFCP Session Modification Response",
                     54: "PFCP Session Deletion Request",
                     55: "PFCP Session Deletion Response",
                     56: "PFCP Session Report Request",
                     57: "PFCP Session Report Response"}


bind_layers(UDP, SessionPFCPHeader, sport=8805)
bind_layers(UDP, SessionPFCPHeader, dport=8805)
