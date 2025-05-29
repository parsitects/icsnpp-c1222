from scapy.all import *
from c1222_enums import *

################################################################################
## 5.2 ASN1 Data Encoding Rules
################################################################################

authSetting = 0

class LengthTypeOctet(Packet):
    name = "Length Type Byte"
    fields_desc = [
        BitField("islong", None, 1), 
        BitField("num", None, 7),
    ]

class LengthType(Packet):
    name = "Length Type"
    fields_desc = [
        PacketListField("octets", [], LengthTypeOctet)
    ]

class ObjectIdentifierNibble(Packet):
    name = "Object Identifier Nibble"
    fields_desc = [
        BitField("data", None, 8),
    ]

class UniversalObjectIdentifier(Packet):
    name = "Universal Object Identifier"
    fields_desc = [
        #ConditionalField(ByteField("main", None), lambda pkt: pkt.tag == pkt.len>1),
        ByteField("main", None),
        PacketListField("sublist", [], ObjectIdentifierNibble)
    ]

class RelativeObjectIdentifier(Packet):
    name = "Relative Object Identifier"
    fields_desc = [
        PacketListField("sublist", [], ObjectIdentifierNibble, count_from=lambda pkt: pkt.len)
    ]

class ID(Packet):
    name = "ID"
    fields_desc = [
        ByteField("tag", None),
        PacketField("len", None, LengthType),
        ConditionalField(PacketField("universalAptitleId", None, UniversalObjectIdentifier), lambda pkt: pkt.tag == IdentifierTags.UNIVERSAL.value),
        ConditionalField(PacketField("relativeAptitleId", None, RelativeObjectIdentifier), lambda pkt: pkt.tag == IdentifierTags.RELATIVE.value)
    ]

################################################################################
## 5.3.2 EPSEM 
################################################################################

class IdentSessionCtrl(Packet):
    name = "IdentSessionCtrl"
    fields_desc = [
        BitField("sessionCtrl", 0, 8),
    ]

class IdentDeviceIdentity(Packet):
    name = "IdentDeviceIdentity"
    fields_desc = [
        ByteField("len", None),
        ByteField("format", None),
        NBytesField("identification", None, 10),
    ]

class IdentFeature(Packet):
    name = "Ident Feature"
    fields_desc = [
        ByteField("tag", None),
        ConditionalField(PacketField("securityMechanism", None, ID), lambda pkt: pkt.tag == IdentFeatureTags.SECURITY_MECHANISM.value),
        ConditionalField(PacketField("sessionCtrl", None, IdentSessionCtrl), lambda pkt: pkt.tag == IdentFeatureTags.SESSION_CTRL.value),
        ConditionalField(PacketField("deviceClass", None, ID), lambda pkt: pkt.tag == IdentFeatureTags.DEVICE_CLASS.value),
        ConditionalField(PacketField("deviceIdentity", None, IdentDeviceIdentity), lambda pkt: pkt.tag == IdentFeatureTags.DEVICE_IDENTITY.value),
    ]

class ReadReqPRead(Packet):
    name = "Read Req PRead"
    fields_desc = [
        ShortField("tableid", None),
        FieldListField("index", [], ShortField("shorts", 0)),
        ShortField("elementCount", None),
    ]

class ReadReqPReadOffset(Packet):
    name = "Read Req PRead Offset"
    fields_desc = [
        ShortField("tableid", None),
        NBytesField("offset", None, 3),
        ShortField("octetCount", None),
    ]

class TableData(Packet):
    name = "Table Data"
    fields_desc = [
        FieldLenField("count_m", None, length_of="data", fmt="H"), # unsigned short format
        StrLenField("data", "", length_from=lambda pkt: pkt.count_m),
        ByteField("cksum", None),
    ]

class ReadRespOk(Packet):
    name = "Read Resp Ok"
    fields_desc = [
        PacketListField("tables", [], TableData),
        PacketListField("extratables", [], TableData)
    ]

class WriteReqFull(Packet):
    name = "Write Req Full"
    fields_desc = [
        ShortField("tableid", None),
        PacketField("table_m", None, TableData),
        ConditionalField(PacketField("extra", None, TableData), lambda pkt: pkt.table_m.count_m == 0xFFFF),
    ]

class WriteReqPWrite(Packet):
    name = "Write Req PWrite"
    fields_desc = [
        ShortField("tableid", None),
        FieldListField("index", [], ShortField),
        PacketField("table_m", None, TableData),
    ]

class WriteReqOffset(Packet):
    name = "Write Req Offset"
    fields_desc = [
        ShortField("tableid", None),
        NBytesField("offset", None, 3),
        PacketField("table_m", None, TableData),
    ]

class LogonReq(Packet):
    name = "Logon Req"
    fields_desc = [
        ShortField("userid", None),
        NBytesField("user", None, 10),
        ShortField("reqSessionTimeout", None),
    ]

class LogonResp(Packet):
    name = "Logon Resp"
    fields_desc = [
        ShortField("respSessionTimeout", None),
    ]

class SecurityReq(Packet):
    name = "Security Req"
    fields_desc = [
        NBytesField("password", None, 20),
        ShortField("userid", None),
    ]

class WaitReq(Packet):
    name = "Wait Req"
    fields_desc = [
        ByteField("timeis", None),
    ]

class RegisterReqDomainPattern(Packet):
    name = "Register Req Domain Pattern"
    fields_desc = [
        FieldLenField("notifPatternLen", None, length_of="notifPattern", fmt="B"), # unsigned 8 bit integer format
        StrLenField("notifPattern", "", length_from=lambda pkt: pkt.notifPatternLen)
    ]

class RegisterReq(Packet):
    name = "Register Req"
    fields_desc = [
        BitField("nodetype", None, 7),
        BitField("isDomain", None, 1),
        BitField("connectionType", None, 8),
        PacketField("deviceClass", None, RelativeObjectIdentifier),
        PacketField("apTitle", None, ID),
        PacketField("electronicSerialNumber", None, ID),
        FieldLenField("addressLen", None, length_of="nativeAddress", fmt="B"), # unsigned 8 bit integer format
        StrLenField("nativeAddress", "", length_from=lambda pkt: pkt.addressLen),
        NBytesField("registrationPeriod", None, 3),
        ConditionalField(PacketField("myDomainPattern", None, RegisterReqDomainPattern), lambda pkt: pkt.isDomain==1),
    ]

class RegisterRespOk(Packet):
    name = "Register Resp Ok"
    fields_desc = [
        PacketField("apTitle", None, ID),
        ShortField("regDelay", None),
        NBytesField("regPeriod", None, 3),
        BitField("regInfo", None, 8),
    ]

class DeregisterReq(Packet):
    name = "Deregister Req"
    fields_desc = [
        PacketField("apTitle", None, ID),
    ]

class ResolveReq(Packet):
    name = "Resolve Req"
    fields_desc = [
        PacketField("apTitle", None, ID),
    ]

class ResolveRespOk(Packet):
    name = "Resolve Resp OK"
    fields_desc = [
        FieldLenField("localAddrLen", None, length_of="localAddr", fmt="B"), # unsigned 8 bit integer format
        StrLenField("localAddr", "", length_from=lambda pkt: pkt.localAddrLen)
    ]

class Trace(Packet):
    name = "Trace"
    fields_desc = [
        PacketListField("trace", [], ID)
    ]

class ResponseNok(Packet):
    name = "Response OK"
    fields_desc = [
        ConditionalField(IntField("maxRequestSize", None), lambda pkt: pkt.code == RequestResponseCodes.RQTL.value),
        ConditionalField(IntField("maxResponseSize", None), lambda pkt: pkt.code == RequestResponseCodes.RSTL.value),
        ConditionalField(StrField("sigerrresp", None), lambda pkt: pkt.code == RequestResponseCodes.SGERR.value), 
        ConditionalField(PacketField("trace", None, Trace), lambda pkt: pkt.code == RequestResponseCodes.TRACE.value),
    ]

class ResponseOkIdent(Packet):
    name = "Response Ok Ident"
    fields_desc = [
        ByteField("std", None),
        ByteField("ver", None),
        ByteField("rev", None),
        PacketListField("features", [], IdentFeature),
        ByteField("eol", None),
    ]

class ResponseOk(Packet):
    name = "Response OK"
    fields_desc = [
        PacketField("identify", None, ResponseOkIdent),
        PacketField("fullread", None, ReadRespOk),
        PacketField("preadone", None, ReadRespOk),
        PacketField("preadtwo", None, ReadRespOk),
        PacketField("preadthree", None, ReadRespOk),
        PacketField("preadfour", None, ReadRespOk),
        PacketField("preadfive", None, ReadRespOk),
        PacketField("preadsix", None, ReadRespOk),
        PacketField("preadseven", None, ReadRespOk),
        PacketField("preadeight", None, ReadRespOk),
        PacketField("preadnine", None, ReadRespOk),
        PacketField("preaddefault", None, ReadRespOk),
        PacketField("preadoffset", None, ReadRespOk),
        #PacketField("fullwrite", None, void),
        #PacketField("pwriteone", None, void),
        #PacketField("pwritetwo", None, void),
        #PacketField("pwritethree", None, void),
        #PacketField("pwritefour", None, void),
        #PacketField("pwritefive", None, void),
        #PacketField("pwritesix", None, void),
        #PacketField("pwriteseven", None, void),
        #PacketField("pwriteeight", None, void),
        #PacketField("pwritenine", None, void),
        #PacketField("pwriteoffset", None, void),),
        PacketField("logon", None, LogonResp),
        #PacketField("security", None, void),
        #PacketField("logoff", None, void),
        #PacketField("terminate", None, void),
        #PacketField("disconnect", None, void),
        #PacketField("wait", None, void),
        PacketField("register", None, RegisterRespOk),
        #PacketField("deregister", None, void),
        PacketField("resolve", None, ResolveRespOk),
        PacketField("trace", None, Trace),
    ]

class Service(Packet):
    name = "Service"
    fields_desc = [
        ByteField("serviceTag", None),
        ConditionalField(PacketField("ok", None, ResponseOk), lambda pkt: pkt.serviceTag == RequestResponseCodes.OK.value),
        ConditionalField(PacketField("err", None, ResponseNok), lambda pkt: pkt.serviceTag == RequestResponseCodes.ERR.value),
        ConditionalField(PacketField("sns", None, ResponseNok), lambda pkt: pkt.serviceTag == RequestResponseCodes.SNS.value),
        ConditionalField(PacketField("isc", None, ResponseNok), lambda pkt: pkt.serviceTag == RequestResponseCodes.ISC.value),
        ConditionalField(PacketField("onp", None, ResponseNok), lambda pkt: pkt.serviceTag == RequestResponseCodes.ONP.value),
        ConditionalField(PacketField("iar", None, ResponseNok), lambda pkt: pkt.serviceTag == RequestResponseCodes.IAR.value),
        ConditionalField(PacketField("bsy", None, ResponseNok), lambda pkt: pkt.serviceTag == RequestResponseCodes.BSY.value),
        ConditionalField(PacketField("dnr", None, ResponseNok), lambda pkt: pkt.serviceTag == RequestResponseCodes.DNR.value),
        ConditionalField(PacketField("dlk", None, ResponseNok), lambda pkt: pkt.serviceTag == RequestResponseCodes.DLK.value),
        ConditionalField(PacketField("rno", None, ResponseNok), lambda pkt: pkt.serviceTag == RequestResponseCodes.RNO.value),
        ConditionalField(PacketField("isss", None, ResponseNok), lambda pkt: pkt.serviceTag == RequestResponseCodes.ISSS.value),
        ConditionalField(PacketField("sme", None, ResponseNok), lambda pkt: pkt.serviceTag == RequestResponseCodes.SME.value),
        ConditionalField(PacketField("uat", None, ResponseNok), lambda pkt: pkt.serviceTag == RequestResponseCodes.UAT.value),
        ConditionalField(PacketField("nett", None, ResponseNok), lambda pkt: pkt.serviceTag == RequestResponseCodes.NETT.value),
        ConditionalField(PacketField("netr", None, ResponseNok), lambda pkt: pkt.serviceTag == RequestResponseCodes.NETR.value),
        ConditionalField(PacketField("rqtl", None, ResponseNok), lambda pkt: pkt.serviceTag == RequestResponseCodes.RQTL.value),
        ConditionalField(PacketField("rstl", None, ResponseNok), lambda pkt: pkt.serviceTag == RequestResponseCodes.RSTL.value),
        ConditionalField(PacketField("sgnp", None, ResponseNok), lambda pkt: pkt.serviceTag == RequestResponseCodes.SGNP.value),
        ConditionalField(PacketField("sgerr", None, ResponseNok), lambda pkt: pkt.serviceTag == RequestResponseCodes.SGERR.value),
        #ConditionalField(PacketField("identify", None, void), lambda pkt: pkt.serviceTag == RequestResponseCodes.IDENT.value),
        ConditionalField(ShortField("fullread", None), lambda pkt: pkt.serviceTag == RequestResponseCodes.FULLREAD.value),
        ConditionalField(PacketField("preadone", None, ReadReqPRead), lambda pkt: pkt.serviceTag == RequestResponseCodes.PREADONE.value),
        ConditionalField(PacketField("preadtwo", None, ReadReqPRead), lambda pkt: pkt.serviceTag == RequestResponseCodes.PREADTWO.value),
        ConditionalField(PacketField("preadthree", None, ReadReqPRead), lambda pkt: pkt.serviceTag == RequestResponseCodes.PREADTHREE.value),
        ConditionalField(PacketField("preadfour", None, ReadReqPRead), lambda pkt: pkt.serviceTag == RequestResponseCodes.PREADFOUR.value),
        ConditionalField(PacketField("preadfive", None, ReadReqPRead), lambda pkt: pkt.serviceTag == RequestResponseCodes.PREADFIVE.value),
        ConditionalField(PacketField("preadsix", None, ReadReqPRead), lambda pkt: pkt.serviceTag == RequestResponseCodes.PREADSIX.value),
        ConditionalField(PacketField("preadseven", None, ReadReqPRead), lambda pkt: pkt.serviceTag == RequestResponseCodes.PREADSEVEN.value),
        ConditionalField(PacketField("preadeight", None, ReadReqPRead), lambda pkt: pkt.serviceTag == RequestResponseCodes.PREADEIGHT.value),
        ConditionalField(PacketField("preadnine", None, ReadReqPRead), lambda pkt: pkt.serviceTag == RequestResponseCodes.PREADNINE.value),
        #ConditionalField(PacketField("preaddefault", None, void), lambda pkt: pkt.serviceTag == RequestResponseCodes.PREADDEFAULT.value),
        ConditionalField(PacketField("preadoffset", None, ReadReqPReadOffset), lambda pkt: pkt.serviceTag == RequestResponseCodes.PREADOFFSET.value),
        ConditionalField(PacketField("fullwrite", None, WriteReqFull), lambda pkt: pkt.serviceTag == RequestResponseCodes.FULLWRITE.value),
        ConditionalField(PacketField("pwriteone", None, WriteReqPWrite), lambda pkt: pkt.serviceTag == RequestResponseCodes.PWRITEONE.value),
        ConditionalField(PacketField("pwritetwo", None, WriteReqPWrite), lambda pkt: pkt.serviceTag == RequestResponseCodes.PWRITETWO.value),
        ConditionalField(PacketField("pwritethree", None, WriteReqPWrite), lambda pkt: pkt.serviceTag == RequestResponseCodes.PWRITETHREE.value),
        ConditionalField(PacketField("pwritefour", None, WriteReqPWrite), lambda pkt: pkt.serviceTag == RequestResponseCodes.PWRITEFOUR.value),
        ConditionalField(PacketField("pwritefive", None, WriteReqPWrite), lambda pkt: pkt.serviceTag == RequestResponseCodes.PWRITEFIVE.value),
        ConditionalField(PacketField("pwritesix", None, WriteReqPWrite), lambda pkt: pkt.serviceTag == RequestResponseCodes.PWRITESIX.value),
        ConditionalField(PacketField("pwriteseven", None, WriteReqPWrite), lambda pkt: pkt.serviceTag == RequestResponseCodes.PWRITESEVEN.value),
        ConditionalField(PacketField("pwriteeight", None, WriteReqPWrite), lambda pkt: pkt.serviceTag == RequestResponseCodes.PWRITEEIGHT.value),
        ConditionalField(PacketField("pwritenine", None, WriteReqPWrite), lambda pkt: pkt.serviceTag == RequestResponseCodes.PWRITENINE.value),
        ConditionalField(PacketField("pwriteoffset", None, WriteReqOffset), lambda pkt: pkt.serviceTag == RequestResponseCodes.PWRITEOFFSET.value),
        ConditionalField(PacketField("logon", None, LogonReq), lambda pkt: pkt.serviceTag == RequestResponseCodes.LOGON.value),
        ConditionalField(PacketField("security", None, SecurityReq), lambda pkt: pkt.serviceTag == RequestResponseCodes.SECURITY.value),
        #ConditionalField(PacketField("logoff", None, void), lambda pkt: pkt.serviceTag == RequestResponseCodes.LOGOFF.value),
        #ConditionalField(PacketField("terminate", None, void), lambda pkt: pkt.serviceTag == RequestResponseCodes.TERMINATE.value),
        #ConditionalField(PacketField("disconnect", None, void), lambda pkt: pkt.serviceTag == RequestResponseCodes.DISCONNECT.value),
        ConditionalField(PacketField("wait", None, WaitReq), lambda pkt: pkt.serviceTag == RequestResponseCodes.WAIT.value),
        ConditionalField(PacketField("register", None, RegisterReq), lambda pkt: pkt.serviceTag == RequestResponseCodes.REGISTER.value),
        ConditionalField(PacketField("deregister", None, DeregisterReq), lambda pkt: pkt.serviceTag == RequestResponseCodes.DEREGISTER.value),
        ConditionalField(PacketField("resolve", None, ResolveReq), lambda pkt: pkt.serviceTag == RequestResponseCodes.RESOLVE.value),
        ConditionalField(PacketField("trace", None, Trace), lambda pkt: pkt.serviceTag == RequestResponseCodes.TRACE.value),
    ]

class EpsemService(Packet):
    name = "Epsem Service"
    fields_desc = [
        PacketField("len", None, LengthType),
        PacketField("service", None, Service),
    ]

################################################################################
## 5.3.3 EPSEM Envelop Structure 
################################################################################

class PlaintextEpsem(Packet):
    name = "Plaintext Epsem"
    fields_desc = [
        PacketListField("data", [], EpsemService),
        StrField("end", None), # Random bytes at the end as filler
    ]

class Epsem(Packet):
    name = "Epsem"
    fields_desc = [
        BitField("extraBits", None, 1), # isn't actually used
        BitField("recoverySession", None, 1),
        BitField("proxyServiceUsed", None, 1),
        BitField("edClassIncluded", None, 1),
        BitField("securityMode", None, 2),
        BitField("responseControl", None, 2),
        ConditionalField(NBytesField("edClass", None, 4), lambda pkt: pkt.edClassIncluded == 1),
        ConditionalField(StrField("encryptedEpsem", None), lambda pkt: pkt.securityMode==2),
        ConditionalField(PacketField("data", None, PlaintextEpsem), lambda pkt: pkt.securityMode==0 or pkt.securityMode==1),
    ]

################################################################################
## 5.3.4 Association Control Service Element (ASCE) 
################################################################################

class CalledAPTitle(Packet):
    name = "Called AP Title"
    fields_desc = [
        PacketField("len", None, LengthType),
        PacketField("apTitle", None, ID),
    ]

class CallingAPTitle(Packet):
    name = "Calling AP Title"
    fields_desc = [
        PacketField("len", None, LengthType),
        PacketField("apTitle", None, ID),
    ]

class CallingApplicationEntityQualifier(Packet):
    name = "Calling Application Entity Qualifier"
    fields_desc = [
        PacketField("integerLen", None, LengthType),
        ByteField("integerTag", 0),
        PacketField("callingAeQualifierLen", None, LengthType),
        BitField("callingAeQualifier", 0, 8)
    ]

class MechanismName(Packet):
    name = "Mechanism Name"
    fields_desc = [
        PacketField("len", None, LengthType),
        PacketField("name", None, UniversalObjectIdentifier),
    ]

class CAVOctetAligned(Packet):
    name = "CAV Octet Aligned"
    fields_desc = [
        PacketField("len", None, LengthType),
        StrLenField("name", None, length_from=lambda pkt: pkt.len.num),
    ]

class CAVIndirectRef(Packet):
    name = "CAV Indirect Ref"
    fields_desc = [
        ByteField("a", None),
        ByteField("b", None),
        ByteField("c", None),
    ]

class C1221AuthIdent(Packet):
    name = "C1221 Auth Ident"
    fields_desc = [
        PacketField("len", None, LengthType),
        StrLenField("authService", None, length_from=lambda pkt: pkt.len.num),
    ]

class C1221AuthReq(Packet):
    name = "C1221 Auth Req"
    fields_desc = [
        PacketField("len", None, LengthType),
        StrLenField("authReq", None, length_from=lambda pkt: pkt.len.num),
    ]

class C1221AuthResp(Packet):
    name = "C1221 Auth Ident"
    fields_desc = [
        PacketField("len", None, LengthType),
        StrLenField("authResp", None, length_from=lambda pkt: pkt.len.num),
    ]

class CallingAuthValC1221(Packet):
    name = "Calling Auth Val C1221"
    fields_desc = [
        PacketField("len", None, LengthType),
        ByteField("msg", None),
        ConditionalField(PacketField("authIdent", None, C1221AuthIdent), lambda pkt: pkt.tag == EncodingC1221Tags.IDENT.value),
        ConditionalField(PacketField("authReq", None, C1221AuthReq), lambda pkt: pkt.tag == EncodingC1221Tags.REQUEST.value),
        ConditionalField(PacketField("authResp", None, C1221AuthResp), lambda pkt: pkt.tag == EncodingC1221Tags.RESPONSE.value),
    ]

class KeyID(Packet):
    name = "Key ID"
    fields_desc = [
        ByteField("tag", None),
        PacketField("len", None, LengthType),
        ByteField("keyId", None),
    ]

class IV(Packet):
    name = "IV"
    fields_desc = [
        ByteField("tag", None),
        PacketField("len", None, LengthType),
        IntField("iv", None),
    ]

class CallingAuthValC1222(Packet):
    name = "Calling Auth Val C1222"
    fields_desc = [
        PacketField("len", None, LengthType),
        PacketField("keyId", None, KeyID),
        PacketField("iv", None, IV),
    ]

class CAVSingleAsn1(Packet):
    name = "CAV Single Asn 1"
    fields_desc = [
        PacketField("len", None, LengthType),
        ByteField("mechanismTag", None),
        ConditionalField(PacketField("c1222Encoding", None, CallingAuthValC1222), lambda pkt: pkt.mechanismTag == EncodingASN1Tags.C1222.value),
        ConditionalField(PacketField("c1221Encoding", None, CallingAuthValC1221), lambda pkt: pkt.mechanismTag == EncodingASN1Tags.C1221.value),
    ]

class CallingAuthenticationValue(Packet):
    name = "Calling Authentication Value"
    fields_desc = [
        PacketField("len", None, LengthType),
        ByteField("externalTag", 0),
        PacketField("externalLen", None, LengthType),
        PacketField("indirectReference", None, CAVIndirectRef),
        ByteField("encodingTag", None),
        ConditionalField(PacketField("singleAsn1", None, CAVSingleAsn1), lambda pkt: pkt.encodingTag == EncodingTags.ASN1.value),
        ConditionalField(PacketField("octetAligned", None, CAVOctetAligned), lambda pkt: pkt.encodingTag == EncodingTags.OCTET.value),
    ]

class CalledApInvocationID(Packet):
    name = "Called Ap Invocation ID"
    fields_desc = [
        PacketField("len", None, LengthType),
        ByteField("intTag", None),
        PacketField("idLen", None, LengthType),
        StrLenField("id", None, length_from=lambda pkt: pkt.idLen.num),
    ]

class CallingAPInvocationID(Packet):
    name = "Calling AP Invocation ID"
    fields_desc = [
        PacketField("len", None, LengthType),
        ByteField("intTag", None),
        PacketField("idLen", None, LengthType),
        StrLenField("id", None, length_from=lambda pkt: pkt.idLen.num),
    ]

class UserInformationFooter(Packet):
    name = "User Information Footer"
    fields_desc = [
        StrField("id", None),
    ]

class UserIndirectRef(Packet):
    name = "User Indirect Ref"
    fields_desc = [
        ByteField("tag", None),
        PacketField("len", None, LengthType),
        ByteField("encoding", None),
    ]

class UserInformation(Packet):
    name = "User Information"
    fields_desc = [
        PacketField("externalLen", None, LengthType),
        ByteField("externalTag", None),
        PacketField("len", None, LengthType),
        PacketField("indirectReference", None, UserIndirectRef),
        ByteField("octetTag", None),
        PacketField("userInfoLen", None, LengthType),
        PacketField("epsem", None, Epsem),
        ConditionalField(PacketField("footer", None, UserInformationFooter), lambda pkt: authSetting == 2),
    ]

class ApplicationContext(Packet):
    name = "Application Context"
    fields_desc = [
        PacketField("len", None, LengthType),
        ByteField("asoContextTag", None),
        PacketField("asoContext", None, ID),
    ]

class Element(Packet):
    name = "Element"
    fields_desc = [
        ByteField("tag", None),
        ConditionalField(PacketField("applicationContext", None, ApplicationContext), lambda pkt: pkt.tag == AsceElementTags.APPLICATION_CONTEXT.value),
        ConditionalField(PacketField("calledApTitle", None, CalledAPTitle), lambda pkt: pkt.tag == AsceElementTags.CALLED_AP_TITLE.value),
        ConditionalField(PacketField("calledApInvocationId", None, CalledApInvocationID), lambda pkt: pkt.tag == AsceElementTags.CALLED_AP_INVOCATION_ID.value),
        ConditionalField(PacketField("callingApTitle", None, CallingAPTitle), lambda pkt: pkt.tag == AsceElementTags.CALLING_AP_TITLE.value),
        ConditionalField(PacketField("callingApplicationEntityQualifier", None, CallingApplicationEntityQualifier), lambda pkt: pkt.tag == AsceElementTags.CALLING_APPLICATION_ENTITY_QUALIFIER.value),
        ConditionalField(PacketField("callingApInvocationId", None, CallingAPInvocationID), lambda pkt: pkt.tag == AsceElementTags.CALLING_AP_INVOCATION_ID.value),
        ConditionalField(PacketField("callingAuthenticationValue", None, CallingAuthenticationValue), lambda pkt: pkt.tag == AsceElementTags.CALLING_AUTHENTICATION_VALUE.value),
        ConditionalField(PacketField("mechanismName", None, MechanismName), lambda pkt: pkt.tag == AsceElementTags.MECHANISM_NAME.value),
        ConditionalField(PacketField("userInformation", None, UserInformation), lambda pkt: pkt.tag == AsceElementTags.USER_INFORMATION.value),
    ]

class AscePdu(Packet):
    name = "AscePdu"
    fields_desc = [
        ByteField("tag", None),
        PacketField("len", None, LengthType),
        PacketListField("elements", [], Element, count_from=lambda pkt: pkt.len.num)
    ]

class Message(Packet):
    name = "Message"
    fields_desc = [
        PacketListField("pdus", [], AscePdu, length_from=lambda pkt: pkt.num_inner)
    ]