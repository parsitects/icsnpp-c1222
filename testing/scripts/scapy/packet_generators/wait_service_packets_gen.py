from scapy.all import *
from c1222_classes import *

wait_service_req=Service(
    serviceTag=RequestResponseCodes.WAIT.value,
    wait=WaitReq(
        timeis=112
    )
)

wait_service_resp=Service(
    serviceTag=RequestResponseCodes.OK.value,
    ok=ResponseOk()
)