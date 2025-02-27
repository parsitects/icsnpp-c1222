module C1222_ENUMS;

################################################################################
## Enums
################################################################################

export {
    const ASCE_ELEMENT_TAGS = {
        [C1222_ENUMS::AsceElementTags_APPLICATION_CONTEXT]                     = "Application Context",
        [C1222_ENUMS::AsceElementTags_CALLED_AP_TITLE]                         = "Called AP Title",
        [C1222_ENUMS::AsceElementTags_CALLED_AP_INVOCATION_ID]                 = "Called AP Invocation ID",
        [C1222_ENUMS::AsceElementTags_CALLING_AP_TITLE]                        = "Calling AP Title",
        [C1222_ENUMS::AsceElementTags_CALLING_APPLICATION_ENTITY_QUALIFIER]    = "Calling Application Entity Qualifier",
        [C1222_ENUMS::AsceElementTags_CALLING_AP_INVOCATION_ID]                = "Calling AP Invocation ID",
        [C1222_ENUMS::AsceElementTags_CALLING_AUTHENTICATION_VALUE]            = "Calling Authentication Value",
        [C1222_ENUMS::AsceElementTags_MECHANISM_NAME]                          = "Mechanism Name",
        [C1222_ENUMS::AsceElementTags_USER_INFORMATION]                        = "User Information"
    }&default = "Unknown Element";

    const IDENTIFIER_TAGS = {
        [C1222_ENUMS::IdentifierTags_UNIVERSAL]   = "Universal ID",
        [C1222_ENUMS::IdentifierTags_RELATIVE]    = "Relative ID"
    }&default = "Unknown";

    const ENCODING_TAGS = {
        [C1222_ENUMS::EncodingTags_ASN1]    = "ASN1",
        [C1222_ENUMS::EncodingTags_OCTET]   = "OCTET"
    }&default = "Unknown";

    const ENCODING_ASN1_TAGS = {
        [C1222_ENUMS::EncodingASN1Tags_C1222] = "C1222",
        [C1222_ENUMS::EncodingASN1Tags_C1221] = "C1221"

    }&default = "Unimplemented";

    const ENCODING_C1221_TAGS = {
        [C1222_ENUMS::EncodingC1221Tags_IDENT]       = "Ident",
        [C1222_ENUMS::EncodingC1221Tags_REQUEST]     = "Request",
        [C1222_ENUMS::EncodingC1221Tags_RESPONSE]    = "Response"
    }&default = "Unknown";

    const REQUEST_RESPONSE_CODES = {
        [C1222_ENUMS::RequestResponseCodes_OK]              = "RESP:OK",
        [C1222_ENUMS::RequestResponseCodes_ERR]             = "RESP:ERR",
        [C1222_ENUMS::RequestResponseCodes_SNS]             = "RESP:SNS",
        [C1222_ENUMS::RequestResponseCodes_ISC]             = "RESP:ISC",
        [C1222_ENUMS::RequestResponseCodes_ONP]             = "RESP:ONP",
        [C1222_ENUMS::RequestResponseCodes_IAR]             = "RESP:IAR",
        [C1222_ENUMS::RequestResponseCodes_BSY]             = "RESP:BSY",
        [C1222_ENUMS::RequestResponseCodes_DNR]             = "RESP:DNR",
        [C1222_ENUMS::RequestResponseCodes_DLK]             = "RESP:DLK",
        [C1222_ENUMS::RequestResponseCodes_RNO]             = "RESP:RNO",
        [C1222_ENUMS::RequestResponseCodes_ISSS]            = "RESP:ISSS",
        [C1222_ENUMS::RequestResponseCodes_SME]             = "RESP:SME",
        [C1222_ENUMS::RequestResponseCodes_UAT]             = "RESP:UAT",
        [C1222_ENUMS::RequestResponseCodes_NETT]            = "RESP:NETT",
        [C1222_ENUMS::RequestResponseCodes_NETR]            = "RESP:NETR",
        [C1222_ENUMS::RequestResponseCodes_RQTL]            = "RESP:RQTL",
        [C1222_ENUMS::RequestResponseCodes_RSTL]            = "RESP:RSTL",
        [C1222_ENUMS::RequestResponseCodes_SGNP]            = "RESP:SGNP",
        [C1222_ENUMS::RequestResponseCodes_SGERR]           = "RESP:SGERR",
        [C1222_ENUMS::RequestResponseCodes_IDENT]           = "REQ:Ident",
        [C1222_ENUMS::RequestResponseCodes_FULLREAD]        = "REQ:Full Read",
        [C1222_ENUMS::RequestResponseCodes_PREADONE]        = "REQ:Partial Read 1",
        [C1222_ENUMS::RequestResponseCodes_PREADTWO]        = "REQ:Partial Read 2",
        [C1222_ENUMS::RequestResponseCodes_PREADTHREE]      = "REQ:Partial Read 3",
        [C1222_ENUMS::RequestResponseCodes_PREADFOUR]       = "REQ:Partial Read 4",
        [C1222_ENUMS::RequestResponseCodes_PREADFIVE]       = "REQ:Partial Read 5",
        [C1222_ENUMS::RequestResponseCodes_PREADSIX]        = "REQ:Partial Read 6",
        [C1222_ENUMS::RequestResponseCodes_PREADSEVEN]      = "REQ:Partial Read 7",
        [C1222_ENUMS::RequestResponseCodes_PREADEIGHT]      = "REQ:Partial Read 8",
        [C1222_ENUMS::RequestResponseCodes_PREADNINE]       = "REQ:Partial Read 9",
        [C1222_ENUMS::RequestResponseCodes_PREADDEFAULT]    = "REQ:Partial Read Default",
        [C1222_ENUMS::RequestResponseCodes_PREADOFFSET]     = "REQ:Partial Read Offset",
        [C1222_ENUMS::RequestResponseCodes_FULLWRITE]       = "REQ:Full Write",
        [C1222_ENUMS::RequestResponseCodes_PWRITEONE]       = "REQ:Partial Write 1",
        [C1222_ENUMS::RequestResponseCodes_PWRITETWO]       = "REQ:Partial Write 2",
        [C1222_ENUMS::RequestResponseCodes_PWRITETHREE]     = "REQ:Partial Write 3",
        [C1222_ENUMS::RequestResponseCodes_PWRITEFOUR]      = "REQ:Partial Write 4",
        [C1222_ENUMS::RequestResponseCodes_PWRITEFIVE]      = "REQ:Partial Write 5",
        [C1222_ENUMS::RequestResponseCodes_PWRITESIX]       = "REQ:Partial Write 6",
        [C1222_ENUMS::RequestResponseCodes_PWRITESEVEN]     = "REQ:Partial Write 7",
        [C1222_ENUMS::RequestResponseCodes_PWRITEEIGHT]     = "REQ:Partial Write 8",
        [C1222_ENUMS::RequestResponseCodes_PWRITENINE]      = "REQ:Partial Write 9",
        [C1222_ENUMS::RequestResponseCodes_PWRITEOFFSET]    = "REQ:Partial Write Offset",
        [C1222_ENUMS::RequestResponseCodes_LOGON]           = "REQ:Logon",
        [C1222_ENUMS::RequestResponseCodes_SECURITY]        = "REQ:Security",
        [C1222_ENUMS::RequestResponseCodes_LOGOFF]          = "REQ:Logoff",
        [C1222_ENUMS::RequestResponseCodes_TERMINATE]       = "REQ:Terminate",
        [C1222_ENUMS::RequestResponseCodes_DISCONNECT]      = "REQ:Disconnect",
        [C1222_ENUMS::RequestResponseCodes_WAIT]            = "REQ:Wait",
        [C1222_ENUMS::RequestResponseCodes_REGISTER]        = "REQ:Register",
        [C1222_ENUMS::RequestResponseCodes_DEREGISTER]      = "REQ:Deregister",
        [C1222_ENUMS::RequestResponseCodes_RESOLVE]         = "REQ:Resolve",
        [C1222_ENUMS::RequestResponseCodes_TRACE]           = "REQ:Trace"
    }&default = "Unknown Code";


    const IDENT_FEATURE_TAGS = {
        [C1222_ENUMS::IdentFeatureTags_SECURITY_MECHANISM]  = "Security Mechanism",
        [C1222_ENUMS::IdentFeatureTags_SESSION_CTRL]        = "Session Control",
        [C1222_ENUMS::IdentFeatureTags_DEVICE_CLASS]        = "Device Class",
        [C1222_ENUMS::IdentFeatureTags_DEVICE_IDENTITY]     = "Device Identity"
    }&default = "Unknown";
}