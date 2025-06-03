from scapy.all import *
from c1222_classes import *

resolve_service_req=Service(
    serviceTag=RequestResponseCodes.RESOLVE.value,
    resolve=ResolveReq(
        apTitle=ID(
            tag=IdentifierTags.UNIVERSAL.value,
            len=LengthType(
                octets=[
                    LengthTypeOctet(
                        num=8,
                        islong=0
                    )
                ]
            ),
            universalAptitleId= UniversalObjectIdentifier(
                main=0x2b,
                sublist=[
                    ObjectIdentifierNibble(data=0x06),
                    ObjectIdentifierNibble(data=0x01),
                    ObjectIdentifierNibble(data=0x04),
                    ObjectIdentifierNibble(data=0x01),
                    ObjectIdentifierNibble(data=0x82),
                    ObjectIdentifierNibble(data=0x85),
                    ObjectIdentifierNibble(data=0x63),
                ]
            )
        )
    )
)

resolve_service_resp=Service(
    serviceTag=RequestResponseCodes.OK.value,
    ok=ResponseOk(
        resolve=ResolveRespOk(
            localAddrLen=12,
            localAddr='localaddress',
        )
    )
)