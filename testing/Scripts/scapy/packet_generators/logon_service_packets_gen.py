from scapy.all import *
from c1222_classes import *

logon_service_req=Service(
    serviceTag=RequestResponseCodes.LOGON.value,
    logon=LogonReq(
        userid=4660,
        user=0x68656c6c6f776f726c64,
        reqSessionTimeout=0
    )
)

logon_service_resp=Service(
    serviceTag=RequestResponseCodes.OK.value,
    ok=ResponseOk(
        logon=LogonResp(
            respSessionTimeout=0
        )
    )
)