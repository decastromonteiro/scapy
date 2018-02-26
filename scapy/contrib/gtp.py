#! /usr/bin/env python

# Copyright (C) 2018 Leonardo Monteiro <decastromonteiro@gmail.com>
#               2017 Alexis Sultan    <alexis.sultan@sfr.com>
#               2017 Alessio Deiana <adeiana@gmail.com>
#               2014 Guillaume Valadon <guillaume.valadon@ssi.gouv.fr>
#               2012 ffranz <ffranz@iniqua.com>
#
# This program is published under a GPLv2 license
# This module is based on 3GPP TS 29.060 - Rel14 - 29.060-e40

# scapy.contrib.description = GTP
# scapy.contrib.status = loads

from __future__ import absolute_import
import time
import logging

from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IP6Field
from scapy.error import warning
from scapy.modules.six.moves import range
from scapy.compat import chb, orb, plain_str

# GTP Data types

# Radio Access Technology Type
# The "RAT Type" information element is used to indicate which Radio Access Technology is currently serving the UE as
# perceived per the SGSN.
RATType = {
    0: "reserved",
    1: "UTRAN",
    2: "GERAN",
    3: "WLAN",
    4: "GAN",
    5: "HSPA Evolution",
    6: "E-UTRAN"
}

# GTP defines a set of messages between two associated GSNs or an SGSN and an RNC.

# GTP Messages Types - Table 1 on 29.060-e40
GTPmessageType = {0: "Unknown Message",
                  1: "Echo Request",
                  2: "Echo Response",
                  3: "Version Not Supported",
                  4: "Node Alive Request",
                  5: "Node Alive Response",
                  6: "Redirection Request",
                  7: "Redirection Response",
                  16: "Create PDP Context Request",
                  17: "Create PDP Context Response",
                  18: "Update PDP Context Request",
                  19: "Update PDP Context Response",
                  20: "Delete PDP Context Request",
                  21: "Delete PDP Context Response",
                  22: "Initiate PDP Context Activation Request",
                  23: "Initiate PDP Context Activation Response",
                  26: "Error Indication",
                  27: "PDU Notification Request",
                  28: "PDU Notification Response",
                  29: "PDU Notification Reject Request",
                  30: "PDU Notification Reject Response",
                  31: "Supported Extension Headers Notification",
                  32: "Send Routeing Information for GPRS Request",
                  33: "Send Routeing Information for GPRS Response",
                  34: "Failure Report Request",
                  35: "Failure Report Response",
                  36: "Note MS GPRS Present Request",
                  37: "Note MS GPRS Present Response",
                  48: "Identification Request",
                  49: "Identification Response",
                  50: "SGSN Context Request",
                  51: "SGSN Context Response",
                  52: "SGSN Context Acknowledge",
                  53: "Forward Relocation Request",
                  54: "Forward Relocation Response",
                  55: "Forward Relocation Complete",
                  56: "Relocation Cancel Request",
                  57: "Relocation Cancel Response",
                  58: "Forward SRNS Context",
                  59: "Forward Relocation Complete Acknowledge",
                  60: "Forward SRNS Context Acknowledge",
                  61: "UE Registration Query Request",
                  62: "UE Registration Query Response",
                  70: "RAN Information Relay",
                  96: "MBMS Notification Request",
                  97: "MBMS Notification Response",
                  98: "MBMS Notification Reject Request",
                  99: "MBMS Notification Reject Response",
                  100: "Create MBMS Context Request",
                  101: "Create MBMS Context Response",
                  102: "Update MBMS Context Request",
                  103: "Update MBMS Context Response",
                  104: "Delete MBMS Context Request",
                  105: "Delete MBMS Context Response",
                  112: "MBMS Registration Request",
                  113: "MBMS Registration Response",
                  114: "MBMS De-Registration Request",
                  115: "MBMS De-Registration Response",
                  116: "MBMS Session Start Request",
                  117: "MBMS Session Start Response",
                  118: "MBMS Session Stop Request",
                  119: "MBMS Session Stop Response",
                  120: "MBMS Session Update Request",
                  121: "MBMS Session Update Response",
                  128: "MS Info Change Notification Request",
                  129: "MS Info Change Notification Response",
                  240: "Data Record Transfer Request",
                  241: "Data Record Transfer Response",
                  254: "End Marker",
                  255: "G-PDU"}

# Information Elements Types - Table 37 on 29.060-e40
IEType = {0: "Reserved.",
          1: "Cause",
          2: "International Mobile Subscriber Identity (IMSI)",
          3: "Routeing Area Identity (RAI)",
          4: "Temporary Logical Link Identity (TTLI)",
          5: "Packet TMSI (P-TMSI)",
          8: "Reordering Required",
          9: "Authentication Triplet",
          11: "MAP Cause",
          12: "P-TMSI Signature",
          13: "MS Validated",
          14: "Recovery",
          15: "Selection Mode",
          16: "Tunnel Endpoint Identifier Data I",
          17: "Tunnel Endpoint Identifier Control Plane",
          18: "Tunnel Endpoint Identifier Data II",
          19: "Teardown Ind",
          20: "NSAPI",
          21: "RANAP Cause",
          22: "RAB Context",
          23: "Radio Priority SMS",
          24: "Radio Priority",
          25: "Packet Flow Id",
          26: "Charging Characteristics",
          27: "Trace Reference",
          28: "Trace Type",
          29: "MS Not Reachable Reason",
          127: "Charging ID",
          128: "End User Address",
          129: "MM Context",
          130: "PDP Context",
          131: "Access Point Name",
          132: "Protocol Configuration Options",
          133: "GSN Address",
          134: "MS International PSTN/ISDN Number (MSISDN)",
          135: "Quality of Service Profile",
          136: "Authentication Quintuplet",
          137: "Traffic Flow Template",
          138: "Target Identification",
          139: "UTRAN Transparent Container",
          140: "RAB Setup Information",
          141: "Extension Header Type List",
          142: "Trigger Id",
          143: "OMC Identity",
          144: "RAN Transparent Container",
          145: "PDP Context Prioritization",
          146: "Additional RAB Setup Information",
          147: "SGSN Number",
          148: "Common Flags",
          149: "APN Restriction",
          150: "Radio Priority LCS",
          151: "RAT Type",
          152: "User Location Information",
          153: "MS Time Zone",
          154: "IMEI(SV)",
          155: "CAMEL Charging Information Container",
          156: "MBMS UE Context",
          157: "Temporary Mobile Group Identity (TMGI)",
          158: "RIM Routing Address",
          159: "MBMS Protocol Configuration Options",
          160: "MBMS Service Area",
          161: "Source RNC PDCP context info",
          162: "Additional Trace Info",
          163: "Hop Counter",
          164: "Selected PLMN ID",
          165: "MBMS Session Identifier",
          166: "MBMS 2G/3G Indicator",
          167: "Enhanced NSAPI",
          168: "MBMS Session Duration",
          169: "Additional MBMS Trace Info",
          170: "MBMS Session Repetition Number",
          171: "MBMS Time To Data Transfer",
          173: "BSS Container",
          174: "Cell Identification",
          175: "PDU Numbers",
          176: "BSSGP Cause",
          177: "Required MBMS bearer capabilities",
          178: "RIM Routing Address Discriminator",
          179: "List of set-up PFCs",
          180: "PS Handover XID Parameters",
          181: "MS Info Change Reporting Action",
          182: "Direct Tunnel Flags",
          183: "Correlation-ID",
          184: "Bearer Control Mode",
          185: "MBMS Flow Identifier",
          186: "MBMS IP Multicast Distribution",
          187: "MBMS Distribution Acknowledgement",
          188: "Reliable INTER RAT HANDOVER INFO",
          189: "RFSP Index",
          190: "Fully Qualified Domain Name (FQDN)",
          191: "Evolved Allocation Retention Priority I",
          192: "Evolved Allocation Retention Priority II",
          193: "Extented Common Flags",
          194: "User CGS Information (UCI)",
          195: "CSG Information Reporting Action",
          196: "CSG ID",
          197: "CSG Membership Indication (CMI)",
          198: "Aggregate Maximum Bit Rate (AMBR)",
          199: "UE Network Capability",
          200: "UE-AMBR",
          201: "APN-AMBR with NSAPI",
          202: "GGSN Back-Off Time",
          203: "Signalling Priority Indication",
          204: "Signalling Priority Indication with NSAPI",
          205: "Higher bitrated than 16 Mbps flag",
          207: "Additional MM context for SRVCC",
          208: "Additional flags for SRVCC",
          209: "STN-SR",
          210: "C-MSISDN",
          211: "Extented RANAP Cause",
          212: "eNodeB ID",
          213: "Selection Mode with NSAPI",
          214: "ULI Timestamp",
          215: "Local Home Network ID (LHN-ID) with NSAPI",
          216: "CN Operator Selection Entity",
          217: "UE Usage Type",
          218: "Extended Common Flags II",
          219: "Node Identifier",
          220: "CloT Optimizations Support Indication",
          221: "SCEF PDN Connection",
          222: "IOV_updated counter",
          223: "Mapped UE Usage Type",
          238: "Special IE Type for IE Type Extension",
          251: "Charging Gateway Address",
          255: "Private Extention"}

# Cause Values - Table 38 on 29.060-e40
CauseValues = {0: "Request IMSI",
               1: "Request IMEI",
               2: "Request IMSI and IMEI",
               3: "No identity needed",
               4: "MS Refuses",
               5: "MS is not GPRS Responding",
               6: "Reactivation Requested",
               7: "PDP address inactivity timer expires",
               8: "Network Failure",
               9: "QoS parameter mismatch",
               128: "Request accepted",
               129: "New PDP type due to network preference",
               130: "New PDP type due to single address bearer only",
               192: "Non-existent",
               193: "Invalid message format",
               194: "IMSI not known",
               195: "MS is GPRS Detached",
               196: "MS is not GPRS Responding",
               197: "MS Refuses",
               198: "Version not supported",
               199: "No resources available",
               200: "Service not supported",
               201: "Mandatory IE incorrect",
               202: "Mandatory IE missing",
               203: "Optional IE incorrect",
               204: "System failure",
               205: "Roaming restriction",
               206: "P-TMSI Signature mismatch",
               207: "GPRS connection suspended",
               208: "Authentication failure",
               209: "User authentication failed",
               210: "Context not found",
               211: "All dynamic PDP addresses are occupied",
               212: "No memory is available",
               213: "Reallocation failure",
               214: "Unknown mandatory extension header",
               215: "Semantic error in the TFT operation",
               216: "Syntactic error in TFT operation",
               217: "Semantic errors in packet filter(s)",
               218: "Syntactic errors in packet filter(s)",
               219: "Missing or unknown APN",
               220: "Unknown PDP address or PDP type",
               221: "PDP context without TFT already activated",
               222: "APN access denied : no subscription",
               223: "APN Restriction type incompatibility with currently active PDP Contexts",
               224: "MS MBMS Capabilities Insufficient",
               225: "Invalid Correlation : ID",
               226: "MBMS Bearer Context Superseded",
               227: "Bearer Control Mode violation",
               228: "Collision with network initiated request",
               229: "APN Congestion",
               230: "Bearer handling not supported",
               231: "Target access restricted for the subscriber",
               232: "UE is temporarily not reachable due to power saving",
               233: "Relocation failure due to NAS message redirection"}

# SelectionMode - Table 42 on 29.060-e40
Selection_Mode = {11111100: "MS or network provided APN, subscribed verified",
                  11111101: "MS provided APN, subscription not verified",
                  11111110: "Network provided APN, subscription not verified",
                  11111111: "For future use. Network provided APN, subscription not verified"}

TrueorFalseValues = {254: "False", 255: "True"}

# Reordering Required Values - Table 40 on 29.060-e40
ReorderingRequiredValues = TrueorFalseValues

# MS Validated Values - Table 41 on 29.060-e40
MSValidatedValues = TrueorFalseValues

# Teardown Indicator Values - Table 43 on 29.060-e40
TeardownIndValues = TrueorFalseValues

# PDP Organization Values - Table 44 on 29.060-e40
PDPTypeOrganizationValues = {0: 'ETSI', 1: 'IETF'}

# http://www.arib.or.jp/IMT-2000/V720Mar09/5_Appendix/Rel8/29/29281-800.pdf
ExtensionHeadersTypes = {
    0: "No more extension headers",
    1: "Reserved",
    2: "Reserved",
    64: "UDP Port",
    192: "PDCP PDU Number",
    193: "Reserved",
    194: "Reserved"
}


class TBCDByteField(StrFixedLenField):

    def i2h(self, pkt, val):
        return val

    def m2i(self, pkt, val):
        ret = []
        for v in val:
            byte = orb(v)
            left = byte >> 4
            right = byte & 0xf
            if left == 0xf:
                ret.append(TBCD_TO_ASCII[right:right + 1])
            else:
                ret += [TBCD_TO_ASCII[right:right + 1], TBCD_TO_ASCII[left:left + 1]]
        return b"".join(ret)

    def i2m(self, pkt, val):
        val = str(val)
        ret_string = ""
        for i in range(0, len(val), 2):
            tmp = val[i:i + 2]
            if len(tmp) == 2:
                ret_string += chr(int(tmp[1] + tmp[0], 16))
            else:
                ret_string += chr(int("F" + tmp[0], 16))
        return ret_string


TBCD_TO_ASCII = b"0123456789*#abc"


class GTP_ExtensionHeader(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return GTP_UDPPort_ExtensionHeader
        return cls


class GTP_UDPPort_ExtensionHeader(GTP_ExtensionHeader):
    fields_desc = [ByteField("length", 0x40),
                   ShortField("udp_port", None),
                   ByteEnumField("next_ex", 0, ExtensionHeadersTypes), ]


class GTP_PDCP_PDU_ExtensionHeader(GTP_ExtensionHeader):
    fields_desc = [ByteField("length", 0x01),
                   ShortField("pdcp_pdu", None),
                   ByteEnumField("next_ex", 0, ExtensionHeadersTypes), ]


class GTPHeader(Packet):
    """
    3GPP TS 29.060-e40 (Section 6)
    The GTP header is a variable length header used for both the GTP-C and the GTP-U protocols.
    The minimum length of the GTP header is 8 bytes.
    """
    name = "GTP Header"
    fields_desc = [BitField("version", 1, 3),
                   BitField("PT", 1, 1),
                   BitField("reserved", 0, 1),
                   BitField("E", 0, 1),
                   BitField("S", 0, 1),
                   BitField("PN", 0, 1),
                   ByteEnumField("gtp_type", None, GTPmessageType),
                   ShortField("length", None),
                   IntField("teid", 0),
                   ConditionalField(XBitField("seq", 0, 16), lambda pkt: pkt.E == 1 or pkt.S == 1 or pkt.PN == 1),
                   ConditionalField(ByteField("npdu", 0), lambda pkt: pkt.E == 1 or pkt.S == 1 or pkt.PN == 1),
                   ConditionalField(ByteEnumField("next_ex", 0, ExtensionHeadersTypes),
                                    lambda pkt: pkt.E == 1 or pkt.S == 1 or pkt.PN == 1), ]

    def post_build(self, p, pay):
        p += pay
        if self.length is None:
            l = len(p) - 8
            p = p[:2] + struct.pack("!H", l) + p[4:]
        return p

    def hashret(self):
        return struct.pack("B", self.version) + struct.pack("I", self.seq)

    def answers(self, other):
        if self.payload.gtp_type == 16:
            return (isinstance(other, GTPHeader) and
                    self.version == other.version and
                    self.seq == other.seq and
                    self.payload.get_teici() == other.teid and
                    self.payload.answers(other.payload))

        if self.payload.gtp_type == 26:
            return (isinstance(other, GTPHeader) and
                    self.version == other.version and
                    self.seq == other.seq)

        return (isinstance(other, GTPHeader) and
                self.version == other.version and
                self.payload.answers(other.payload) and
                self.seq == other.seq)

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 1:
            if (orb(_pkt[0]) >> 5) & 0x7 == 2:
                from . import gtp_v2
                return gtp_v2.GTPHeader
        if _pkt and len(_pkt) >= 8:
            _gtp_type = orb(_pkt[1:2])
            return GTPforcedTypes.get(_gtp_type, GTPHeader)
        return cls


# Some gtp_types have to be associated with a certain type of header
GTPforcedTypes = {
    16: GTPHeader,
    17: GTPHeader,
    18: GTPHeader,
    19: GTPHeader,
    20: GTPHeader,
    21: GTPHeader,
    26: GTP_U_Header,
    27: GTPHeader,
    254: GTP_U_Header,
    255: GTP_U_Header
}


class IE_Base(Packet):

    def extract_padding(self, pkt):
        return "", pkt


class IE_Cause(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.1) In a request, the Cause Value indicates the reason for the request. The Cause
    shall be included in the request message. In a response, the Cause Value indicates the acceptance or the
    rejection of the corresponding request. In addition, the Cause Value may indicate what was the reason for the
    corresponding request. The Cause value shall be included in the response message.
    """
    name = "Cause"
    fields_desc = [ByteEnumField("ietype", 1, IEType),
                   ByteEnumField("CauseValue", 128, CauseValues)]


class IE_IMSI(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.2) The IMSI shall be the subscriber identity of the MS. The IMSI is TBCD-coded
    with a fixed length of 8 octets.
    """
    name = "International Mobile Subscriber Identity (IMSI)"
    fields_desc = [ByteEnumField("ietype", 2, IEType),
                   TBCDByteField("imsi", str(RandNum(0, 999999999999999)), 8)]


class IE_RAI(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.3)
    """
    name = "Routing Area Identity (RAI)"
    fields_desc = [ByteEnumField("ietype", 3, IEType),
                   TBCDByteField("MCC", "", 2),
                   # MNC: if the third digit of MCC is 0xf,
                   # then the length of MNC is 1 byte
                   TBCDByteField("MNC", "", 1),
                   ShortField("LAC", None),
                   ByteField("RAC", None)]


class IE_TLLI(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.4) The information element of the TLLI is associated with a given MS and routing
    area.
    """
    name = "Temporary Logical Link identity (TLLI)"
    fields_desc = [ByteEnumField("ietype", 4, IEType),
                   BitField("tlli", 0, 32)]


class IE_PTMSI(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.5) The Packet TMSI is unambiguously associated with a given MS and routeing area.
    """
    name = "Packet TMSI (P-TMSI)"
    fields_desc = [ByteEnumField("ietype", 5, IEType),
                   BitField("ptmsi", 0, 32)]


class IE_ReorderingRequired(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.6) The Reordering Required information element states whether reordering by GTP
    is required or not.
    """
    name = "Reordering Required"
    fields_desc = [ByteEnumField("ietype", 8, IEType),
                   ByteEnumField("reordering_required", 254, ReorderingRequiredValues)]


class IE_AuthenticationTriplet(IE_Base):
    """
    3GPP TS 29.060 (Section 7.7.7) An Authentication triplet consists of a Random string (RAND), a Signed Response (
    SRES) and a ciphering Key (Kc) (see 3GPP TS 43.020).
    """
    name = "Authentication Triplet"
    # todo: Check 3GPP TS 43.020 to se encode of RAND, SRES and Kc
    fields_desc = [ByteEnumField("ietype", 9, IEType),
                   BitField("rand", 0, 128),
                   BitField("sres", 0, 32),
                   BitField("kc", 0, 64)]


class IE_MAPCause(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.8) The MAP Cause is a value that the GTP-MAP protocol-converting GSN relays
    transparently from HLR to the GGSN.
    """
    name = "MAP Cause"
    fields_desc = [ByteEnumField("ietype", 11, IEType),
                   ByteField("map_cause", 0)]


class IE_PTMSISignature(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.9) The P-TMSI Signature information element is provided by the MS in the Routing
    Area Update Request and Attach Request messages to the SGSN for identification checking purposes.
    """
    name = "P-TMSI Signature"
    fields_desc = [ByteEnumField("ietype", 12, IEType),
                   BitField("ptmsi_signature", 0, 24)]


class IE_MSValidated(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.10) The MS Validated information element indicates whether the new SGSN has
    successfully authenticated the MS.
    """
    name = "MS Validated"
    fields_desc = [ByteEnumField("ietype", 13, IEType),
                   ByteEnumField("ms_validated", 254, MSValidatedValues)]


class IE_Recovery(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.11) The Recovery information element indicates if the peer GSN has restarted. The
    Restart Counter shall be the value described in the section Restoration and Recovery.
    """
    name = "Recovery"
    fields_desc = [ByteEnumField("ietype", 14, IEType),
                   ByteField("restart_counter", 24)]


class IE_SelectionMode(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.12) The Selection mode information element indicates the origin of the APN in the
    message.
    """
    name = "Selection Mode"
    fields_desc = [ByteEnumField("ietype", 15, IEType),
                   BitEnumField("SelectionMode", "MS or network provided APN, subscribed verified", 8, Selection_Mode)]


class IE_TEIDI(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.13) The Tunnel Endpoint Identifier Data I information element contains the Tunnel
    Endpoint Identifier for data transmission requested by the receiver of the flow.
    """
    name = "Tunnel Endpoint Identifier Data I"
    fields_desc = [ByteEnumField("ietype", 16, IEType),
                   XIntField("TEIDI", RandInt())]


class IE_TEICP(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.14) The Tunnel Endpoint Identifier Control Plane information element contains the
    Tunnel Endpoint Identifier for the control plane; it is assigned by the receiver of the flow. It distinguishes
    the tunnel from other tunnels between the same pair of entities.
    """
    name = "Tunnel Endpoint Identifier Control Plane"
    fields_desc = [ByteEnumField("ietype", 17, IEType),
                   XIntField("TEICI", RandInt())]


class IE_TEIDII(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.15) The Tunnel Endpoint Identifier Data II information element contains the
    Tunnel Endpoint Identifier for data transmission between old and new SGSN for a particular PDP context and is
    requested by the new SGSN.
    """
    name = "Tunnel Endpoint Identifier Data II"
    fields_desc = [ByteEnumField("ietype", 18, IEType),
                   XBitField("sparebits", 0x0, 4),
                   XBitField("nsapi", RandNum(0, 15), 4),
                   XIntField("teidii", RandInt())]


class IE_TeardownInd(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.16) If the Teardown Ind information element value is set to "1", then all PDP
    contexts that share the same PDN connection with the PDP context identified by the NSAPI included  in the Delete
    PDP Context Request Message shall be torn down. Only the PDP context identified by the NSAPI included in the
    Delete PDP context Request shall be torn down if the value of this information element is "0".
    """
    name = "Teardown Indicator"
    fields_desc = [ByteEnumField("ietype", 19, IEType),
                   ByteEnumField("indicator", "True", TeardownIndValues)]


class IE_NSAPI(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.17) The NSAPI information element contains an NSAPI identifying a PDP Context in
    a mobility management context specified by the Tunnel Endpoint Identifier Control Plane.
    """
    name = "NSAPI"
    fields_desc = [ByteEnumField("ietype", 20, IEType),
                   XBitField("sparebits", 0x0, 4),
                   XBitField("nsapi", RandNum(0, 15), 4)]


class IE_RANAPCause(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.18) The RANAP Cause information element contains the cause as defined in 3GPP TS
    25.413. The value part (which has a range of 1..255) of the RANAP Cause IE which is transferred over the Iu
    interface is encoded into one octet from the binary encoding of the value part of the RANAP Cause IE.
    """
    name = "RANAP Cause"
    fields_desc = [ByteEnumField("ietype", 21, IEType),
                   ByteField("ranap_cause", 0)]


class IE_RABContext(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.19) The RAB context information element contains sequence number status for one
    RAB in RNC, which corresponds to one PDP context in CN.  The RAB contexts are transferred between the RNCs via
    the SGSNs at inter SGSN hard handover. NSAPI identifies the PDP context and the associated RAB for which the RAB
    context IE is intended. DL GTP-U Sequence Number is the number for the next downlink GTP-U T-PDU to be sent to
    the MS. UL GTP-U Sequence Number is the number for the next uplink GTP-U T-PDU to be tunnelled to the GGSN. DL
    PDCP Sequence Number is the number for the next downlink PDCP-PDU to be sent to the MS. UL PDCP Sequence Number
    is the number for the next uplink PDCP-PDU to be received from the MS.
    """
    name = "RAB Context"
    fields_desc = [ByteEnumField("ietype", 22, IEType),
                   XBitField("sparebits", 0x0, 4),
                   XBitField("nsapi", RandNum(0, 15), 4),
                   XBitField("dl_gtpu_seq", 0x0000, 16),
                   XBitField("ul_gtpu_seq", 0x0000, 16),
                   XBitField("dl_pdpcp_seq", 0x0000, 16),
                   XBitField("ul_pdpcp_seq", 0x0000, 16)]


class IE_RadioPrioritySMS(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.20) The Radio Priority SMS information element contains the radio priority level
    for MO SMS transmission.
    """
    name = "Radio Priority SMS"
    fields_desc = [ByteEnumField("ietype", 23, IEType),
                   XBitField("sparebits", 0x0, 5),
                   XBitField("radio_priority_sms", RandNum(0, 7), 3)]


class IE_RadioPriority(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.21) The Radio Priority information element contains the radio priority level that
    the MS uses when accessing the network for the transmission of uplink user data for a PDP context as identified
    by NSAPI.
    """
    name = "Radio Priority"
    fields_desc = [ByteEnumField("ietype", 24, IEType),
                   XBitField("nsapi", RandNum(0, 15), 4),
                   BitField("sparebits", 0, 1),
                   XBitField("radio_priority", RandNum(0, 7), 3)]


class IE_PacketFlowId(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.22) The Packet Flow Id information element contains the packet flow identifier
    assigned to a PDP context as identified by NSAPI.
    """
    name = "Packet Flow Id"
    fields_desc = [ByteEnumField("ietype", 25, IEType),
                   XBitField("sparebits", 0x0, 4),
                   XBitField("nsapi", RandNum(0, 15), 4),
                   XByteField("packet_flow_id", RandNum(0, 255))]


class IE_ChargingCharacteristics(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.23) The charging characteristics information element is a way of informing both
    the SGSN and GGSN of the rules for producing charging information based on operator configured triggers. For the
    encoding of this information element see 3GPP TS 32.298.
    """
    name = "Charging Characteristics"
    fields_desc = [ByteEnumField("ietype", 26, IEType),
                   # producing charging information based on operator configured triggers.
                   #    0000 .... .... .... : spare
                   #    .... 1... .... .... : normal charging
                   #    .... .0.. .... .... : prepaid charging
                   #    .... ..0. .... .... : flat rate charging
                   #    .... ...0 .... .... : hot billing charging
                   #    .... .... 0000 0000 : reserved
                   XBitField("Ch_ChSpare", None, 4),
                   XBitField("normal_charging", None, 1),
                   XBitField("prepaid_charging", None, 1),
                   XBitField("flat_rate_charging", None, 1),
                   XBitField("hot_billing_charging", None, 1),
                   XBitField("Ch_ChReserved", 0, 8)]


class IE_TraceReference(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.24) The Trace Reference information element identifies a record or a collection
    of records for a particular trace. The Trace Reference is allocated by the triggering entity.
    """
    name = "Trace Reference"
    fields_desc = [ByteEnumField("ietype", 27, IEType),
                   XBitField("trace_reference", None, 16)]


class IE_TraceType(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.25) The Trace Type information element indicates the type of the trace.
    """
    name = "Trace Type"
    fields_desc = [ByteEnumField("ietype", 28, IEType),
                   XBitField("Trace_type", None, 16)]


class IE_MSNotReachableReason(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.25A) The MS Not Reachable Reason indicates the reason for the setting of the MNRG
    flag.
    """
    name = "MS Not Reachable Reason"
    fields_desc = [ByteEnumField("ietype", 29, IEType),
                   ByteField("reason_for_absence", None)]


class IE_RadioPriorityLCS(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.25B) The Radio Priority LCS information element contains the radio priority level
    for MO LCS transmission.
    """
    name = "Radio Priority LCS"
    fields_desc = [ByteEnumField("ietype", 150, IEType),
                   ShortField("length", 1),
                   XBitField("sparebits", 0, 5),
                   XBitField("radio_priority_lcs", 0, 3)]


class IE_ChargingID(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.26) The Charging ID is a unique four-octet value generated by the GGSN when a PDP
    context is activated. A Charging ID is generated for each activated context. The Charging ID value 0 is reserved
    and shall not be assigned by the GGSN.
    """
    name = "Charging ID"
    fields_desc = [ByteEnumField("ietype", 127, IEType),
                   XIntField("charging_id", RandInt())]


class IE_EndUserAddress(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.27) The purpose of the End User Address information element shall be to supply
    protocol specific information of the external packet data network accessed by the GPRS subscriber.
    """
    name = "End User Address"
    fields_desc = [ByteEnumField("ietype", 128, IEType),
                   #         data network accessed by the GGPRS subscribers.
                   #            - Request
                   #                1    Type (1byte)
                   #                2-3    Length (2bytes) - value 2
                   #                4    Spare + PDP Type Organization
                   #                5    PDP Type Number
                   #            - Response
                   #                6-n    PDP Address
                   ShortField("length", 2),
                   BitField("spare", 15, 4),
                   BitEnumField("pdptypeorganization", 1, 4, PDPTypeOrganizationValues),
                   XByteField("pdptypenumber", None),
                   ConditionalField(IPField("PDPAddress", RandIP()),
                                    lambda pkt: pkt.length == 6 or pkt.length == 22),
                   ConditionalField(IP6Field("IPv6_PDPAddress", '::1'),
                                    lambda pkt: pkt.length == 18 or pkt.length == 22)]


class APNStrLenField(StrLenField):
    # Inspired by DNSStrField
    def m2i(self, pkt, s):
        ret_s = b""
        tmp_s = s
        while tmp_s:
            tmp_len = orb(tmp_s[0]) + 1
            if tmp_len > len(tmp_s):
                warning("APN prematured end of character-string (size=%i, remaining bytes=%i)" % (tmp_len, len(tmp_s)))
            ret_s += tmp_s[1:tmp_len]
            tmp_s = tmp_s[tmp_len:]
            if len(tmp_s):
                ret_s += b"."
        s = ret_s
        return s

    def i2m(self, pkt, s):
        s = b"".join(chb(len(x)) + x for x in s.split("."))
        return s


class IE_AccessPointName(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.30) The Access Point Name is sent by the SGSN or by GGSN as defined in 3GPP TS
    23.060 [4]. The Access Point Name contains a logical name (see 3GPP TS 23.060 [4]). It is coded as in the value
    part defined in 3GPP TS 24.008 [5] (i.e. the 3GPP TS 24.008 [5] IEI and 3GPP TS 24.008 [5] octet length indicator
    are not included).
    """
    name = "Access Point Name"
    fields_desc = [ByteEnumField("ietype", 131, IEType),
                   ShortField("length", None),
                   APNStrLenField("APN", "nternet", length_from=lambda x: x.length)]

    def post_build(self, p, pay):
        if self.length is None:
            l = len(p) - 3
            p = p[:2] + struct.pack("!B", l) + p[3:]
        return p


class IE_ProtocolConfigurationOptions(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.31) The Protocol Configuration Options contains external network protocol options
    that may be necessary to transfer between the GGSN and the MS. The content and the coding of the Protocol
    Configuration are defined in octet 3-z of the Protocol Configuration Options in subclause 10.5.6.3 of 3GPP TS
    24.008. Please refer to subclause 10.5.6.3 of 3GPP TS 24.008 for the maximum length of Protocol
    Configuration Options.
    """
    name = "Protocol Configuration Options"
    fields_desc = [ByteEnumField("ietype", 132, IEType),
                   ShortField("length", 4),
                   StrLenField("Protocol_Configuration", "",
                               length_from=lambda x: x.length)]


class IE_GSNAddress(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.32) The GSN Address information element contains the address of a GSN as defined
    in 3GPP TS 23.003. The Address Type and Address Length fields from 3GPP TS 23.003 are not included in the
    GSN Address field.
    """
    name = "GSN Address"
    fields_desc = [ByteEnumField("ietype", 133, IEType),
                   ShortField("length", 4),
                   IPField("address", RandIP())]


class IE_MSISDN(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.33) The MS international ISDN numbers are allocated from the ITU-T Recommendation
    E.164 numbering plan.
    """
    name = "MS International PSTN/ISDN Number (MSISDN)"
    fields_desc = [ByteEnumField("ietype", 134, IEType),
                   ShortField("length", None),
                   FlagsField("flags", 0x91, 8,
                              ["Extension", "", "", "International Number", "", "", "", "ISDN numbering"]),
                   TBCDByteField("digits", "33607080910", length_from=lambda x: x.length - 1)]


class IE_QoSProfile(IE_Base):
    """
    3GPP TS 29.060-e40 (Section 7.7.34) The Quality of Service (QoS) Profile shall include the values of the defined
    QoS parameters.
    """
    name = "QoS profile"
    fields_desc = [ByteField("qos_ei", 0),
                   ByteField("length", None),
                   XBitField("spare", 0x00, 2),
                   XBitField("delay_class", 0x000, 3),
                   XBitField("reliability_class", 0x000, 3),
                   XBitField("peak_troughput", 0x0000, 4),
                   BitField("spare", 0, 1),
                   XBitField("precedence_class", 0x000, 3),
                   XBitField("spare", 0x000, 3),
                   XBitField("mean_troughput", 0x00000, 5),
                   XBitField("traffic_class", 0x000, 3),
                   XBitField("delivery_order", 0x00, 2),
                   XBitField("delivery_of_err_sdu", 0x000, 3),
                   ByteField("max_sdu_size", None),
                   ByteField("max_bitrate_up", None),
                   ByteField("max_bitrate_down", None),
                   XBitField("redidual_ber", 0x0000, 4),
                   XBitField("sdu_err_ratio", 0x0000, 4),
                   XBitField("transfer_delay", 0x00000, 5),
                   XBitField("traffic_handling_prio", 0x000, 3),
                   ByteField("guaranteed_bit_rate_up", None),
                   ByteField("guaranteed_bit_rate_down", None)]


class IE_QoS(IE_Base):
    name = "QoS"
    fields_desc = [ByteEnumField("ietype", 135, IEType),
                   ShortField("length", None),
                   ByteField("allocation_retention_prioiry", 1),

                   ConditionalField(XBitField("spare", 0x00, 2),
                                    lambda pkt: pkt.length > 1),
                   ConditionalField(XBitField("delay_class", 0x000, 3),
                                    lambda pkt: pkt.length > 1),
                   ConditionalField(XBitField("reliability_class", 0x000, 3),
                                    lambda pkt: pkt.length > 1),

                   ConditionalField(XBitField("peak_troughput", 0x0000, 4),
                                    lambda pkt: pkt.length > 2),
                   ConditionalField(BitField("spare", 0, 1),
                                    lambda pkt: pkt.length > 2),
                   ConditionalField(XBitField("precedence_class", 0x000, 3),
                                    lambda pkt: pkt.length > 2),

                   ConditionalField(XBitField("spare", 0x000, 3),
                                    lambda pkt: pkt.length > 3),
                   ConditionalField(XBitField("mean_troughput", 0x00000, 5),
                                    lambda pkt: pkt.length > 3),

                   ConditionalField(XBitField("traffic_class", 0x000, 3),
                                    lambda pkt: pkt.length > 4),
                   ConditionalField(XBitField("delivery_order", 0x00, 2),
                                    lambda pkt: pkt.length > 4),
                   ConditionalField(XBitField("delivery_of_err_sdu", 0x000, 3),
                                    lambda pkt: pkt.length > 4),

                   ConditionalField(ByteField("max_sdu_size", None),
                                    lambda pkt: pkt.length > 5),
                   ConditionalField(ByteField("max_bitrate_up", None),
                                    lambda pkt: pkt.length > 6),
                   ConditionalField(ByteField("max_bitrate_down", None),
                                    lambda pkt: pkt.length > 7),

                   ConditionalField(XBitField("redidual_ber", 0x0000, 4),
                                    lambda pkt: pkt.length > 8),
                   ConditionalField(XBitField("sdu_err_ratio", 0x0000, 4),
                                    lambda pkt: pkt.length > 8),
                   ConditionalField(XBitField("transfer_delay", 0x00000, 6),
                                    lambda pkt: pkt.length > 9),
                   ConditionalField(XBitField("traffic_handling_prio",
                                              0x000,
                                              2),
                                    lambda pkt: pkt.length > 9),

                   ConditionalField(ByteField("guaranteed_bit_rate_up", None),
                                    lambda pkt: pkt.length > 10),
                   ConditionalField(ByteField("guaranteed_bit_rate_down",
                                              None),
                                    lambda pkt: pkt.length > 11),

                   ConditionalField(XBitField("spare", 0x000, 3),
                                    lambda pkt: pkt.length > 12),
                   ConditionalField(BitField("signaling_indication", 0, 1),
                                    lambda pkt: pkt.length > 12),
                   ConditionalField(XBitField("source_stats_desc", 0x0000, 4),
                                    lambda pkt: pkt.length > 12),

                   ConditionalField(ByteField("max_bitrate_down_ext", None),
                                    lambda pkt: pkt.length > 13),
                   ConditionalField(ByteField("guaranteed_bitrate_down_ext",
                                              None),
                                    lambda pkt: pkt.length > 14),
                   ConditionalField(ByteField("max_bitrate_up_ext", None),
                                    lambda pkt: pkt.length > 15),
                   ConditionalField(ByteField("guaranteed_bitrate_up_ext",
                                              None),
                                    lambda pkt: pkt.length > 16),
                   ConditionalField(ByteField("max_bitrate_down_ext2", None),
                                    lambda pkt: pkt.length > 17),
                   ConditionalField(ByteField("guaranteed_bitrate_down_ext2",
                                              None),
                                    lambda pkt: pkt.length > 18),
                   ConditionalField(ByteField("max_bitrate_up_ext2", None),
                                    lambda pkt: pkt.length > 19),
                   ConditionalField(ByteField("guaranteed_bitrate_up_ext2",
                                              None),
                                    lambda pkt: pkt.length > 20)]


class IE_CommonFlags(IE_Base):
    name = "Common Flags"
    fields_desc = [ByteEnumField("ietype", 148, IEType),
                   ShortField("length", None),
                   BitField("dual_addr_bearer_fl", 0, 1),
                   BitField("upgrade_qos_supported", 0, 1),
                   BitField("nrsn", 0, 1),
                   BitField("no_qos_nego", 0, 1),
                   BitField("mbms_cnting_info", 0, 1),
                   BitField("ran_procedure_ready", 0, 1),
                   BitField("mbms_service_type", 0, 1),
                   BitField("prohibit_payload_compression", 0, 1)]


class IE_APNRestriction(IE_Base):
    name = "APN Restriction"
    fields_desc = [ByteEnumField("ietype", 149, IEType),
                   ShortField("length", 1),
                   ByteField("restriction_type_value", 0)]


class IE_RATType(IE_Base):
    name = "Rat Type"
    fields_desc = [ByteEnumField("ietype", 151, IEType),
                   ShortField("length", 1),
                   ByteEnumField("RAT_Type", None, RATType)]


class IE_UserLocationInformation(IE_Base):
    name = "User Location Information"
    fields_desc = [ByteEnumField("ietype", 152, IEType),
                   ShortField("length", None),
                   ByteField("type", 1),
                   # Only type 1 is currently supported
                   TBCDByteField("MCC", "", 2),
                   # MNC: if the third digit of MCC is 0xf, then the length of MNC is 1 byte
                   TBCDByteField("MNC", "", 1),
                   ShortField("LAC", None),
                   ShortField("SAC", None)]


class IE_MSTimeZone(IE_Base):
    name = "MS Time Zone"
    fields_desc = [ByteEnumField("ietype", 153, IEType),
                   ShortField("length", None),
                   XByteField("timezone", 0x00),
                   BitField("Spare", 0, 1),
                   BitField("Spare", 0, 1),
                   BitField("Spare", 0, 1),
                   BitField("Spare", 0, 1),
                   BitField("Spare", 0, 1),
                   BitField("Spare", 0, 1),
                   XBitField("daylight_saving_time", 0x00, 2)]


class IE_IMEI(IE_Base):
    name = "IMEI"
    fields_desc = [ByteEnumField("ietype", 154, IEType),
                   ShortField("length", None),
                   TBCDByteField("IMEI", "", length_from=lambda x: x.length)]


class IE_MSInfoChangeReportingAction(IE_Base):
    name = "MS Info Change Reporting Action"
    fields_desc = [ByteEnumField("ietype", 181, IEType),
                   ShortField("length", 1),
                   ByteField("Action", 0)]


class IE_DirectTunnelFlags(IE_Base):
    name = "Direct Tunnel Flags"
    fields_desc = [ByteEnumField("ietype", 182, IEType),
                   ShortField("length", 1),
                   BitField("Spare", 0, 1),
                   BitField("Spare", 0, 1),
                   BitField("Spare", 0, 1),
                   BitField("Spare", 0, 1),
                   BitField("Spare", 0, 1),
                   BitField("EI", 0, 1),
                   BitField("GCSI", 0, 1),
                   BitField("DTI", 0, 1)]


class IE_BearerControlMode(IE_Base):
    name = "Bearer Control Mode"
    fields_desc = [ByteEnumField("ietype", 184, IEType),
                   ShortField("length", 1),
                   ByteField("bearer_control_mode", 0)]


class IE_EvolvedAllocationRetentionPriority(IE_Base):
    name = "Evolved Allocation/Retention Priority"
    fields_desc = [ByteEnumField("ietype", 191, IEType),
                   ShortField("length", 1),
                   BitField("Spare", 0, 1),
                   BitField("PCI", 0, 1),
                   XBitField("PL", 0x0000, 4),
                   BitField("Spare", 0, 1),
                   BitField("PVI", 0, 1)]


class IE_CharginGatewayAddress(IE_Base):
    name = "Chargin Gateway Address"
    fields_desc = [ByteEnumField("ietype", 251, IEType),
                   ShortField("length", 4),
                   ConditionalField(IPField("ipv4_address", "127.0.0.1"),
                                    lambda pkt: pkt.length == 4),
                   ConditionalField(IP6Field("ipv6_address", "::1"),
                                    lambda pkt: pkt.length == 16)]


class IE_PrivateExtension(IE_Base):
    name = "Private Extension"
    fields_desc = [ByteEnumField("ietype", 255, IEType),
                   ShortField("length", 1),
                   ByteField("extension identifier", 0),
                   StrLenField("extention_value", "",
                               length_from=lambda x: x.length)]


class IE_ExtensionHeaderList(IE_Base):
    name = "Extension Header List"
    fields_desc = [ByteEnumField("ietype", 141, IEType),
                   FieldLenField("length", None, length_of="extension_headers"),
                   FieldListField("extension_headers", [64, 192], ByteField("", 0))]


class IE_NotImplementedTLV(Packet):
    name = "IE not implemented"
    fields_desc = [ByteEnumField("ietype", 0, IEType),
                   ShortField("length", None),
                   StrLenField("data", "", length_from=lambda x: x.length)]

    def extract_padding(self, pkt):
        return "", pkt


class IE_CorrelationID(Packet):
    """
    3GPP TS 29.060-e40 (Section 7.7.82) The Correlation-ID is used in the GGSN to correlate the subsequent Secondary
    PDP Context Activation Procedure with the Initiate PDP Context Activation Request message in the Network
    Requested Secondary PDP Context Activation Procedure.
    """
    name = "Correlation-ID"
    fields_desc = [ByteEnumField("ietype", 183, IEType),
                   ShortField("length", 1),
                   XByteField("correlation_id", 0)]


ietypecls = {1: IE_Cause,
             2: IE_IMSI,
             3: IE_RAI,
             8: IE_ReorderingRequired,
             14: IE_Recovery,
             15: IE_SelectionMode,
             16: IE_TEIDI,
             17: IE_TEICP,
             19: IE_Teardown,
             20: IE_NSAPI,
             26: IE_ChargingCharacteristics,
             27: IE_TraceReference,
             28: IE_TraceType,
             127: IE_ChargingId,
             128: IE_EndUserAddress,
             131: IE_AccessPointName,
             132: IE_ProtocolConfigurationOptions,
             133: IE_GSNAddress,
             134: IE_MSISDN,
             135: IE_QoS,
             141: IE_ExtensionHeaderList,
             148: IE_CommonFlags,
             149: IE_APNRestriction,
             151: IE_RATType,
             152: IE_UserLocationInformation,
             153: IE_MSTimeZone,
             154: IE_IMEI,
             181: IE_MSInfoChangeReportingAction,
             182: IE_DirectTunnelFlags,
             184: IE_BearerControlMode,
             191: IE_EvolvedAllocationRetentionPriority,
             251: IE_CharginGatewayAddress,
             255: IE_PrivateExtension}


def IE_Dispatcher(s):
    """Choose the correct Information Element class."""
    if len(s) < 1:
        return Raw(s)
    # Get the IE type
    ietype = orb(s[0])
    cls = ietypecls.get(ietype, Raw)

    # if ietype greater than 128 are TLVs
    if cls == Raw and ietype & 128 == 128:
        cls = IE_NotImplementedTLV
    return cls(s)


# Path Management Messages

class GTPEchoRequest(Packet):
    """
    3GPP TS 29.060-e40 (Section 7.2.1) A GSN or an RNC may send an Echo Request on a path to the other GSN or RNC to
    find out if the peer GSN or RNC is alive (see section Path Failure). Echo Request messages may be sent for each
    path associated with at least one of the active PDP context, or MBMS UE context, or MBMS bearer context. When and
    how often an Echo Request message may be sent is implementation specific but an Echo Request shall not be sent
    more often than every 60 s on each path.
    """
    gtp_type = 1
    answer_gtp_type = 2
    name = "GTP Echo Request"

    def answers(self, other):
        return self.answer_gtp_type == other.gtp_type


class GTPEchoResponse(Packet):
    """
    3GPP TS 29.060-e40 (Section 7.2.2)
    The message shall be sent as a response to a received Echo Request.
    """
    gtp_type = 2
    name = "GTP Echo Response"
    fields_desc = [PacketListField("IE_list", [IE_Recovery()], IE_Dispatcher)]

    def answers(self, other):
        return self.gtp_type == other.answer_gtp_type


class GTPVersionNotSupported:
    """
    3GPP TS 29.060 (Section 7.2.3) This message contains only the GTP header and indicates the latest GTP version
    that the GTP entity on the identified UDP/IP address can support.
    """
    gtp_type = 3
    name = 'Version not Supported'


class GTPSupportedExtensionHeadersNotification(Packet):
    """
    3GPP TS 29.060-e40 (Section 7.2.4) This message indicates a list of supported Extension Headers that the GTP
    entity on the identified IP address can support. This message is sent only in case a GTP entity was required to
    interpret a mandatory Extension Header but the GSN or RNC was not yet upgraded to support that extension header.
    """
    gtp_type = 31
    name = "GTP Supported Extension Headers Notification"
    fields_desc = [PacketListField("IE_list", [IE_ExtensionHeaderList()], IE_Dispatcher)]


# Tunnel Management Messages

class GTPCreatePDPContextRequest(Packet):
    """
    3GPP TS 29.060-e40 (Section 7.3.1) A Create PDP Context Request shall be sent from a SGSN node to a GGSN node as
    a part of the GPRS PDP Context Activation procedure.
    """
    gtp_type = 16
    answer_gtp_type = 17
    name = "GTP Create PDP Context Request"
    fields_desc = [PacketListField("IE_list", [IE_IMSI(), IE_RAI(), IE_SelectionMode(),
                                               IE_TEIDI(), IE_TEICP(), IE_NSAPI(),
                                               IE_ChargingCharacteristics(), IE_EndUserAddress(),
                                               IE_AccessPointName(), IE_ProtocolConfigurationOptions(),
                                               IE_GSNAddress(), IE_GSNAddress(), IE_MSISDN(),
                                               IE_QoSProfile(), IE_CommonFlags(), IE_RATType(),
                                               IE_UserLocationInformation(), IE_MSTimeZone(),
                                               IE_IMEI(), IE_EvolvedAllocationRetentionPriority()], IE_Dispatcher)]

    def get_teici(self):
        """Returns the TEID Control Plane to be compared with CreatePDPContextResponse GTPHeader's TEID"""
        for IE in self.IE_list:
            if IE.ietype == 17:
                return IE.TEICI

    def answers(self, other):
        return self.answer_gtp_type == other.gtp_type


class GTPCreatePDPContextResponse(Packet):
    """ 
    3GPP TS 29.060-e40 (Section 7.3.2)
    The message shall be sent from a GGSN node to a SGSN node as a response of a Create PDP Context Request.
    """
    gtp_type = 17
    name = "GTP Create PDP Context Response"
    fields_desc = [PacketListField("IE_list", [IE_Cause(), IE_TEIDI(), IE_TEICP(), IE_NSAPI(), IE_ChargingId(),
                                               IE_EndUserAddress(), IE_ProtocolConfigurationOptions(), IE_GSNAddress(),
                                               IE_GSNAddress(), IE_QoS(), IE_CharginGatewayAddress(),
                                               IE_CommonFlags(), IE_BearerControlMode(), ], IE_Dispatcher)]

    def answers(self, other):
        return self.gtp_type == other.answer_gtp_type


class GTPUpdatePDPContextRequest(Packet):
    """
    3GPP TS 29.060-e40 (Section 7.3.3)
    An Update PDP Context Request message shall be sent from an SGSN to a GGSN as part of 
    the GPRS inter-SGSN Routeing Area Update procedure, the PDP Context Modification procedure,
    to redistribute contexts due to load sharing or as part of the inter-system intra SGSN update procedure i.e. 
    UE transitioning between UTRAN and GERAN A/Gb mode (and vice versa) on the same SGSN and if the SGSN decides 
    to enable a direct GTP-U tunnel between the GGSN and the RNC. It shall be used to change the QoS and the path.
    Information Elements List will change accordingly to NE sending this messages. Reference: Table 7 and Table 8
    """
    gtp_type = 18
    answer_gtp_type = 19
    name = "GTP Update PDP Context Request"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]

    def answers(self, other):
        return self.answer_gtp_type == other.gtp_type


class GTPUpdatePDPContextResponse(Packet):
    """
    3GPP TS 29.060-e40 (Section 7.3.4)
    The message shall be sent from a GGSN node to a SGSN node as a response of an Update PDP Context Request.
    Information Elements List will change accordingly to NE sending this messages. Reference: Table 9 and Table 10
    """
    gtp_type = 19
    name = "GTP Update PDP Context Response"
    fields_desc = [PacketListField("IE_list", [IE_Cause()], IE_Dispatcher)]

    def hashret(self):
        return struct.pack("H", self.gtp_type)

    def answers(self, other):
        return self.gtp_type == other.answer_gtp_type


class GTPDeletePDPContextRequest(Packet):
    """
    3GPP TS 29.060-e40 (Section 7.3.5)
    A Delete PDP Context Request shall be sent from a SGSN node to a GGSN node as part of the GPRS Detach procedure 
    or the GPRS PDP Context Deactivation procedure or from a GGSN node to a SGSN node as part of 
    the PDP Context Deactivation Initiated by GGSN procedure.
    A request shall be used to deactivate an activated PDP Context or an activated set of 
    PDP contexts associated to a PDN connection. 
    The Delete PDP Context Request shall also be used as part of the UTRAN (HSPA) to UTRAN/GERAN SRVCC Procedure 
    when the source node is a Gn/Gp SGSN as specified in 3GPP TS 23.216. 
    The message shall be sent from a GGSN node to a SGSN node as a response of an Update PDP Context Request.
    """
    gtp_type = 20
    answer_gtp_type = 21
    name = "GTP Delete PDP Context Request"
    fields_desc = [PacketListField("IE_list", [IE_NSAPI(), IE_Teardown()], IE_Dispatcher)]

    def answers(self, other):
        return self.answer_gtp_type == other.gtp_type


class GTPDeletePDPContextResponse(Packet):
    """
    3GPP TS 29.060-e40 (Section 7.3.6)
    The message shall be sent as a response of a Delete PDP Context Request. 
    A GSN shall delete PDP context(s) when GSN receives Delete PDP Context Request message..
    """
    gtp_type = 21
    name = "GTP Delete PDP Context Response"
    fields_desc = [PacketListField("IE_list", [IE_Cause()], IE_Dispatcher)]

    def answers(self, other):
        return self.gtp_type == other.answer_gtp_type


class GTPErrorIndication(Packet):
    """
    3GPP TS 29.060-e40 (Section 7.3.7)
    Error Indication message is specified in 3GPP TS 29.281.
    """
    gtp_type = 26
    name = "GTP Error Indication"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class GTPPDUNotificationRequest(Packet):
    """
    3GPP TS 29.060-e40 (Section 7.3.8)
    """
    gtp_type = 27
    answer_gtp_type = 28
    name = "GTP PDU Notification Request"
    fields_desc = [PacketListField("IE_list", [IE_IMSI(), IE_TEICP(TEICI=RandInt()),
                                               IE_EndUserAddress(PDPTypeNumber=0x21),
                                               IE_AccessPointName(),
                                               IE_GSNAddress(address="127.0.0.1")], IE_Dispatcher)]

    def answers(self, other):
        return self.answer_gtp_type == other.gtp_type


class GTPPDUNotificationResponse(Packet):
    """
    3GPP TS 29.060-e40 (Section 7.3.9)
    The message is sent by a SGSN to GGSN as a response of a PDU Notification Request.
    """
    gtp_type = 28
    name = "GTP PDU Notification Response"
    fields_desc = [PacketListField("IE_list", [IE_Cause()], IE_Dispatcher)]

    def answers(self, other):
        return self.gtp_type == other.answer_gtp_type


class GTPPDUNotificationRejectRequest(Packet):
    """
    3GPP TS 29.060-e40 (Section 7.3.10)
    """
    gtp_type = 29
    answer_gtp_type = 30
    name = "GTP PDU Notification Reject Request"
    fields_desc = [PacketListField("IE_list", [IE_Cause(), IE_TEICP(TEICI=RandInt()),
                                               IE_EndUserAddress(PDPTypeNumber=0x21),
                                               IE_AccessPointName()], IE_Dispatcher)]

    def answers(self, other):
        return self.answer_gtp_type == other.gtp_type


class GTPPDUNotificationRejectResponse(Packet):
    """
    3GPP TS 29.060-e40 (Section 7.3.11)
    The message is sent by a GGSN to SGSN as a response of a PDU Notification Reject Request.
    """
    gtp_type = 30
    name = "GTP PDU Notification Reject Response"
    fields_desc = [PacketListField("IE_list", [IE_Cause()], IE_Dispatcher)]

    def answers(self, other):
        return self.gtp_type == other.answer_gtp_type


class GTPInitiatePDPContextActivationRequest(Packet):
    """
    3GPP TS 29.060-e40 (Section 7.3.12)
    """
    gtp_type = 22
    answer_gtp_type = 23
    name = "GTP Initiate PDP Context Activation Request"
    fields_desc = [PacketListField("IE_list", [IE_NSAPI(), IE_QoSProfile(), IE_CorrelationID()], IE_Dispatcher)]

    def answers(self, other):
        return self.answer_gtp_type == other.gtp_type


class GTPInitiatePDPContextActivationResponse(Packet):
    """
    3GPP TS 29.060-e40 (Section 7.3.13)
    """
    gtp_type = 23
    name = " GTP Initiate PDP Context Activation Response"
    fields_desc = [PacketListField("IE_list", [IE_Cause()], IE_Dispatcher)]

    def answers(self, other):
        return self.gtp_type == other.answer_gtp_type


class GTPmorethan1500(Packet):
    # 3GPP TS 29.060 V9.1.0 (2009-12)
    name = "GTP More than 1500"
    fields_desc = [ByteEnumField("IE_Cause", "Cause", IEType),
                   BitField("IE", 1, 12000), ]


# Bind GTP-C
bind_layers(UDP, GTPHeader, dport=2123)
bind_layers(UDP, GTPHeader, sport=2123)
# Bind GTP-C Path Management Messages
bind_layers(GTPHeader, GTPEchoRequest, gtp_type=GTPEchoRequest.gtp_type, S=1)
bind_layers(GTPHeader, GTPEchoResponse, gtp_type=GTPEchoResponse.gtp_type, S=1)
# Bind GTP-C Tunnel Management Messages
bind_layers(GTPHeader, GTPCreatePDPContextRequest, gtp_type=GTPCreatePDPContextRequest.gtp_type, S=1)
bind_layers(GTPHeader, GTPCreatePDPContextResponse, gtp_type=GTPCreatePDPContextResponse.gtp_type, S=1)
bind_layers(GTPHeader, GTPUpdatePDPContextRequest, gtp_type=GTPUpdatePDPContextRequest.gtp_type, S=1)
bind_layers(GTPHeader, GTPUpdatePDPContextResponse, gtp_type=GTPUpdatePDPContextResponse.gtp_type, S=1)
bind_layers(GTPHeader, GTPDeletePDPContextRequest, gtp_type=GTPDeletePDPContextRequest.gtp_type, S=1)
bind_layers(GTPHeader, GTPDeletePDPContextResponse, gtp_type=GTPDeletePDPContextResponse.gtp_type, S=1)
bind_layers(GTPHeader, GTPPDUNotificationRequest, gtp_type=GTPPDUNotificationRequest.gtp_type, S=1)
bind_layers(GTPHeader, GTPPDUNotificationResponse, gtp_type=GTPPDUNotificationResponse.gtp_type, S=1)
bind_layers(GTPHeader, GTPPDUNotificationRejectRequest, gtp_type=GTPPDUNotificationRejectRequest.gtp_type, S=1)
bind_layers(GTPHeader, GTPPDUNotificationRejectResponse, gtp_type=GTPPDUNotificationRejectResponse.gtp_type, S=1)
bind_layers(GTPHeader, GTPInitiatePDPContextActivationRequest,
            gtp_type=GTPInitiatePDPContextActivationRequest.gtp_type, S=1)
bind_layers(GTPHeader, GTPInitiatePDPContextActivationResponse,
            gtp_type=GTPInitiatePDPContextActivationResponse.gtp_type, S=1)
# Bind GTP-C Extension Header
bind_layers(GTPHeader, GTPSupportedExtensionHeadersNotification,
            gtp_type=GTPSupportedExtensionHeadersNotification.gtp_type, S=1)
bind_layers(GTPHeader, GTP_UDPPort_ExtensionHeader, next_ex=64, E=1)
bind_layers(GTPHeader, GTP_PDCP_PDU_ExtensionHeader, next_ex=192, E=1)

# Bind GTP-U
bind_layers(UDP, GTPHeader, dport=2152)
bind_layers(UDP, GTPHeader, sport=2152)
bind_layers(GTPHeader, GTPErrorIndication, gtp_type=GTPErrorIndication.gtp_type, S=1)
bind_layers(GTPHeader, IP, gtp_type=255)

if __name__ == "__main__":
    from scapy.all import *

    interact(mydict=globals(), mybanner="GTPv1 add-on")
