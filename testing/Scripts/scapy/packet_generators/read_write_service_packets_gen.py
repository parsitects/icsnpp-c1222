from scapy.all import *
from c1222_classes import *

rw_service=Service(
    serviceTag=RequestResponseCodes.PREADONE.value,
    preadone=ReadReqPRead(
        tableid=0,
        index=[
            0
        ],
        elementCount=0
    )
)