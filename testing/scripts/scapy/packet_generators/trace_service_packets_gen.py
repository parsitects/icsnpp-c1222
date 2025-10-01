from scapy.all import *
from c1222_classes import *

trace_service_req=Service(
    serviceTag=RequestResponseCodes.TRACE.value,
    trace=Trace(
        trace = [
            ID(
                tag=IdentifierTags.UNIVERSAL.value,
                len=LengthType(
                    octets=[
                        LengthTypeOctet(
                            num=8,
                            islong=0
                        )
                    ]
                ),
                universalAptitleId = UniversalObjectIdentifier(
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
        ]
    )
)

trace_service_resp=Service(
    serviceTag=RequestResponseCodes.OK.value,
    ok=ResponseOk(
        trace=Trace(
            trace = [
                ID(
                    tag=IdentifierTags.UNIVERSAL.value,
                    len=LengthType(
                        octets=[
                            LengthTypeOctet(
                                num=8,
                                islong=0
                            )
                        ]
                    ),
                    universalAptitleId = UniversalObjectIdentifier(
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
                ),
                ID(
                                        tag=IdentifierTags.UNIVERSAL.value,
                    len=LengthType(
                        octets=[
                            LengthTypeOctet(
                                num=15,
                                islong=0
                            )
                        ]
                    ),
                    universalAptitleId = UniversalObjectIdentifier(
                        main=0x2b,
                        sublist=[
                            ObjectIdentifierNibble(data=0x06),
                            ObjectIdentifierNibble(data=0x01),
                            ObjectIdentifierNibble(data=0x04),
                            ObjectIdentifierNibble(data=0x01),
                            ObjectIdentifierNibble(data=0x82),
                            ObjectIdentifierNibble(data=0x85),
                            ObjectIdentifierNibble(data=0x63),
                            ObjectIdentifierNibble(data=0x8e),
                            ObjectIdentifierNibble(data=0x7f),
                            ObjectIdentifierNibble(data=0x85),
                            ObjectIdentifierNibble(data=0xf1),
                            ObjectIdentifierNibble(data=0xc2),
                            ObjectIdentifierNibble(data=0x4e),
                            ObjectIdentifierNibble(data=0x00),
                        ]
                    )
                )
            ]
        )
    )
)