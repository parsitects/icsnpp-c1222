from scapy.all import *
from c1222_classes import *

rw_service_req=Service(
    serviceTag=RequestResponseCodes.PREADONE.value,
    preadone=ReadReqPRead(
        tableid=0,
        index=[
            0
        ],
        elementCount=1
    )
)

rw_service_resp=Service(
    serviceTag=RequestResponseCodes.OK.value,
    ok=ResponseOk(
        preadone=ReadRespOk(
            tables=[
                TableData(
                    count_m=8,
                    data="testdata",
                    cksum=0
                )
            ],
            extratables=[]
        )
    )
)