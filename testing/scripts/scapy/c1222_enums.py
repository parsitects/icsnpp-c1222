from enum import Enum

class AsceElementTags(Enum):
    APPLICATION_CONTEXT                     = 0xA1
    CALLED_AP_TITLE                         = 0xA2
    CALLED_AP_INVOCATION_ID                 = 0xA4
    CALLING_AP_TITLE                        = 0xA6
    CALLING_APPLICATION_ENTITY_QUALIFIER    = 0xA7
    CALLING_AP_INVOCATION_ID                = 0xA8
    CALLING_AUTHENTICATION_VALUE            = 0xAC
    MECHANISM_NAME                          = 0x8B
    USER_INFORMATION                        = 0xBE

class IdentifierTags(Enum):
    UNIVERSAL   = 0x06
    RELATIVE    = 0x80

class EncodingTags(Enum):
    ASN1    = 0xA0
    OCTET   = 0x81

class EncodingASN1Tags(Enum):
    C1222 = 0xA1
    C1221 = 0xA0

class EncodingC1221Tags(Enum):
    IDENT       = 0x80
    REQUEST     = 0x81
    RESPONSE    = 0x82

class RequestResponseCodes(Enum):
    OK              = 0x00
    ERR             = 0x01
    SNS             = 0x02
    ISC             = 0x03
    ONP             = 0x04
    IAR             = 0x05
    BSY             = 0x06
    DNR             = 0x07
    DLK             = 0x08
    RNO             = 0x09
    ISSS            = 0x0A
    SME             = 0x0B
    UAT             = 0x0C
    NETT            = 0x0D
    NETR            = 0x0E
    RQTL            = 0x0F
    RSTL            = 0x10
    SGNP            = 0x11
    SGERR           = 0x12
    IDENT           = 0x20
    FULLREAD        = 0x30
    PREADONE        = 0x31
    PREADTWO        = 0x32
    PREADTHREE      = 0x33
    PREADFOUR       = 0x34
    PREADFIVE       = 0x35
    PREADSIX        = 0x36
    PREADSEVEN      = 0x37
    PREADEIGHT      = 0x38
    PREADNINE       = 0x39
    PREADDEFAULT    = 0x3E
    PREADOFFSET     = 0x3F
    FULLWRITE       = 0x40
    PWRITEONE       = 0x41
    PWRITETWO       = 0x42
    PWRITETHREE     = 0x43
    PWRITEFOUR      = 0x44
    PWRITEFIVE      = 0x45
    PWRITESIX       = 0x46
    PWRITESEVEN     = 0x47
    PWRITEEIGHT     = 0x48
    PWRITENINE      = 0x49
    PWRITEOFFSET    = 0x4F
    LOGON           = 0x50
    SECURITY        = 0x51
    LOGOFF          = 0x52
    TERMINATE       = 0x21
    DISCONNECT      = 0x22
    WAIT            = 0x70
    REGISTER        = 0x27
    DEREGISTER      = 0x24
    RESOLVE         = 0x25
    TRACE           = 0x26

class IdentFeatureTags(Enum):
    SECURITY_MECHANISM  = 0x04
    SESSION_CTRL        = 0x05
    DEVICE_CLASS        = 0x06
    DEVICE_IDENTITY     = 0x07