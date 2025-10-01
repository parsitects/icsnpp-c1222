from scapy.all import *
from c1222_classes import *

def createMessageFromService(serviceIn, reqresp):

    if(reqresp == "req"):
        calledApTitle = UniversalObjectIdentifier(
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
        callingApTitle = UniversalObjectIdentifier(
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
        len1 = 0x11
        len2 = 15
        len3 = 0x0a
        len4 = 8


    elif(reqresp == "resp"):
        callingApTitle = UniversalObjectIdentifier(
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
        calledApTitle = UniversalObjectIdentifier(
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
        len1 = 0x0a
        len2 = 8
        len3 = 0x11
        len4 = 15


    message = Message(
        pdus=[
            AscePdu(
                tag=0x60,
                len=LengthType(
                    octets=[
                        LengthTypeOctet(
                            num=47+len(serviceIn),
                            islong=0
                        ),
                    ]
                ),
                elements=[
                    Element(
                        tag=AsceElementTags.CALLED_AP_TITLE.value,
                        calledApTitle=CalledAPTitle(
                            len=LengthType(
                                octets=[
                                    LengthTypeOctet(
                                        num=len1,
                                        islong=0
                                    )
                                ]
                            ),
                            apTitle=ID(
                                tag=IdentifierTags.UNIVERSAL.value,
                                len=LengthType(
                                    octets=[
                                        LengthTypeOctet(
                                            num=len2,
                                            islong=0
                                        )
                                    ]
                                ),
                                universalAptitleId=calledApTitle
                            )
                        )
                    ),
                    Element(
                        tag=AsceElementTags.CALLING_AP_TITLE.value,
                        callingApTitle=CallingAPTitle(
                            len=LengthType(
                                octets=[
                                    LengthTypeOctet(
                                        num=len3,
                                        islong=0
                                    )
                                ]
                            ),
                            apTitle=ID(
                                tag=IdentifierTags.UNIVERSAL.value,
                                len=LengthType(
                                    octets=[
                                        LengthTypeOctet(
                                            num=len4,
                                            islong=0
                                        )
                                    ]
                                ),
                                universalAptitleId=callingApTitle
                            )
                        )
                    ),
                    Element(
                        tag=AsceElementTags.CALLING_AP_INVOCATION_ID.value,
                        callingApInvocationId=CallingAPInvocationID(
                            len=LengthType(
                                octets=[
                                    LengthTypeOctet(
                                        num=6,
                                        islong=0
                                    ),
                                ]
                            ),
                            intTag=2,
                            idLen=LengthType(
                                octets=[
                                    LengthTypeOctet(
                                        num=4,
                                        islong=0
                                    ),
                                ]
                            ),
                            id=b"\x13\xe8\x14\x21"
                        )
                    ),
                    ##NOT USED IN PLAINTEXT PACKETS
                    #Element(
                    #    tag=AsceElementTags.CALLING_AUTHENTICATION_VALUE.value,
                    #    callingAuthenticationValue=CallingAuthenticationValue(
                    #        len=LengthType(
                    #            octets=[
                    #                LengthTypeOctet(
                    #                   num=0x0f,
                    #                    islong=0
                    #                ),
                    #            ]
                    #        ),
                    #        externalTag=0xa2,
                    #        externalLen=LengthType(
                    #            octets=[
                    #                LengthTypeOctet(
                    #                    num=0x0d,
                    #                    islong=0
                    #                ),
                    #            ]
                    #        ),
                    #        #It has no CAVIndirectRef for this one...
                    #        #indirectReference=CAVIndirectRef(
                    #        #    a=0xa0,
                    #        #    b=0x0b,
                    #        #    c=0xa1,
                    #        #),
                    #        encodingTag=EncodingTags.ASN1.value,
                    #        singleAsn1=CAVSingleAsn1(
                    #            len=LengthType(
                    #                octets=[
                    #                    LengthTypeOctet(
                    #                        num=0x0b,
                    #                        islong=0
                    #                    ),
                    #                ]
                    #            ),
                    #            mechanismTag=EncodingASN1Tags.C1222.value,
                    #            c1222Encoding=CallingAuthValC1222(
                    #                len=LengthType(
                    #                    octets=[
                    #                        LengthTypeOctet(
                    #                            num=9,
                    #                            islong=0
                    #                        ),
                    #                    ]
                    #                ),
                    #                keyId=KeyID(
                    #                    tag=0x80,
                    #                    len=LengthType(
                    #                        octets=[
                    #                            LengthTypeOctet(
                    #                                num=1,
                    #                                islong=0
                    #                            ),
                    #                        ]
                    #                    ),
                    #                    keyId=0
                    #                ),
                    #                iv=IV(
                    #                    tag=0x81,
                    #                    len=LengthType(
                    #                        octets=[
                    #                            LengthTypeOctet(
                    #                                num=4,
                    #                                islong=0
                    #                            ),
                    #                        ]
                    #                    ),
                    #                    iv=1285026953
                    #                )
                    #            ),
                    #        )
                    #    )
                    #),
                    Element(
                        tag=AsceElementTags.USER_INFORMATION.value,
                        userInformation=UserInformation(
                            externalLen=LengthType(
                                octets=[
                                    LengthTypeOctet(
                                        num=6+len(serviceIn),
                                        islong=0
                                    ),
                                ]
                            ),
                            externalTag=0x28,
                            len=LengthType(
                                octets=[
                                    LengthTypeOctet(
                                        num=4+len(serviceIn),
                                        islong=0
                                    ),
                                ]
                            ),
                            # we don't do the indirect ref in this packet
                            #indirectReference=UserIndirectRef(
                            #    tag=0,
                            #    len=LengthType(
                            #        octets=[
                            #            LengthTypeByte(
                            #                num=0,
                            #                islong=0
                            #            ),
                            #        ]
                            #    ),
                            #    encoding=0
                            #),
                            octetTag=0x81,
                            userInfoLen=LengthType(
                                octets=[
                                    LengthTypeOctet(
                                        num=2+len(serviceIn),
                                        islong=0
                                    ),
                                ]
                            ),
                            epsem=Epsem(
                                extraBits=1,
                                recoverySession=0,
                                proxyServiceUsed=0,
                                edClassIncluded=0,
                                securityMode=0,
                                responseControl=0,
                                data=PlaintextEpsem(
                                    data=[
                                        EpsemService(
                                            len=LengthType(
                                                octets=[
                                                    LengthTypeOctet(
                                                        num=len(serviceIn),
                                                        islong=0
                                                    ),
                                                ]
                                            ),
                                            service=serviceIn
                                        )
                                    ]
                                )
                            )
                        )
                    ),
                ]
            )
        ]
    )
    return message;