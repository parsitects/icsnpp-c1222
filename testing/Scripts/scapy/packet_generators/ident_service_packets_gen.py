from scapy.all import *
from c1222_classes import *

commandType = RequestResponseCodes.IDENT.value

ident_service=Service(
    serviceTag=RequestResponseCodes.OK.value,
    ok=ResponseOk(
        identify=ResponseOkIdent(
            std=0,
            ver=0,
            rev=0,
            features=[
                IdentFeature(
                    tag=0
                )
            ],
            eol=0
        )
    )
)