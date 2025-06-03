from scapy.all import *
from c1222_classes import *

security_service_req=Service(
    serviceTag=RequestResponseCodes.SECURITY.value,
    security=SecurityReq(
        password=0x70617373776F726431323334,
        userid=1234,
    )
)

security_service_resp=Service(
    serviceTag=RequestResponseCodes.OK.value,
    ok=ResponseOk()
)