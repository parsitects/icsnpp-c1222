module C1222;

hook set_session_summary_log(c: connection) {
    if ( ! c?$c1222_summary_log )
        c$c1222_summary_log = summary_log(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto=get_conn_transport_proto(c$id));
}

hook set_authentication_value_log(c: connection) {
    if ( ! c?$c1222_authentication_value_log )
        c$c1222_authentication_value_log = authentication_value_log(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto=get_conn_transport_proto(c$id));
}

hook set_user_information_log(c: connection) {
    if ( ! c?$c1222_user_information_log )
        c$c1222_user_information_log = user_information_log(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto=get_conn_transport_proto(c$id));
}

hook set_identification_service_log(c: connection) {
    if (! c?$c1222_identification_service_log)
        c$c1222_identification_service_log = identification_service_log(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto=get_conn_transport_proto(c$id));
}

function getIdString(ID: Zeek_C1222::ID): string{
    local tag = ID$tag;
    local returnVal: string;
    switch tag {
        case C1222::IdentifierTags_UNIVERSAL:
            returnVal = ID$universalAptitleId$oidstring;
            break;
        case C1222::IdentifierTags_RELATIVE:
            returnVal = ID$relativeAptitleId$oidstring;
            break;
    }
    return returnVal;
}

function getServiceVectorLog(services: vector of Zeek_C1222::EpsemService): vector of string {
    local service_vector: vector of string;

    for (i, item in services) {

        switch item$service$serviceTag {
        case C1222::RequestResponseCodes_ERR:
            service_vector += "Resp:ERR";
            break;
        case C1222::RequestResponseCodes_OK:
            service_vector += "Resp:OK";
            break;
        case C1222::RequestResponseCodes_SNS:
            service_vector += "Resp:SNS";
            break;
        case C1222::RequestResponseCodes_ISC:
            service_vector += "Resp:ISC";
            break;
        case C1222::RequestResponseCodes_ONP:
            service_vector += "Resp:ONP";
            break;
        case C1222::RequestResponseCodes_IAR:
            service_vector += "Resp:IAR";
            break;
        case C1222::RequestResponseCodes_BSY:
            service_vector += "Resp:BSY";
            break;
        case C1222::RequestResponseCodes_DNR:
            service_vector += "Resp:DNR";
            break;
        case C1222::RequestResponseCodes_DLK:
            service_vector += "Resp:DLK";
            break;
        case C1222::RequestResponseCodes_RNO:
            service_vector += "Resp:RNO";
            break;
        case C1222::RequestResponseCodes_ISSS:
            service_vector += "Resp:ISSS";
            break;
        case C1222::RequestResponseCodes_SME:
            service_vector += "Resp:SME";
            break;
        case C1222::RequestResponseCodes_UAT:
            service_vector += "Resp:UAT";
            break;
        case C1222::RequestResponseCodes_NETT:
            service_vector += "Resp:NETT";
            break;
        case C1222::RequestResponseCodes_NETR:
            service_vector += "Resp:NETR";
            break;
        case C1222::RequestResponseCodes_RQTL:
            service_vector += "Resp:RQTL";
            break;
        case C1222::RequestResponseCodes_RSTL:
            service_vector += "Resp:RSTL";
            break;
        case C1222::RequestResponseCodes_SGNP:
            service_vector += "Resp:SGNP";
            break;
        case C1222::RequestResponseCodes_SGERR:
            service_vector += "Resp:SGERR";
            break;
        case C1222::RequestResponseCodes_IDENT:
            service_vector += "Req:IDENT";
            break;
        case C1222::RequestResponseCodes_FULLREAD:
            service_vector += "Req:FULLREAD";
            break;
        case C1222::RequestResponseCodes_PREADONE:
            service_vector += "Req:PARTIAL_READ_1";
            break;
        case C1222::RequestResponseCodes_PREADTWO:
            service_vector += "Req:PARTIAL_READ_2";
            break;
        case C1222::RequestResponseCodes_PREADTHREE:
            service_vector += "Req:PARTIAL_READ_3";
            break;
        case C1222::RequestResponseCodes_PREADFOUR:
            service_vector += "Req:PARTIAL_READ_4";
            break;
        case C1222::RequestResponseCodes_PREADFIVE:
            service_vector += "Req:PARTIAL_READ_5";
            break;
        case C1222::RequestResponseCodes_PREADSIX:
            service_vector += "Req:PARTIAL_READ_6";
            break;
        case C1222::RequestResponseCodes_PREADSEVEN:
            service_vector += "Req:PARTIAL_READ_7";
            break;
        case C1222::RequestResponseCodes_PREADEIGHT:
            service_vector += "Req:PARTIAL_READ_8";
            break;
        case C1222::RequestResponseCodes_PREADNINE:
            service_vector += "Req:PARTIAL_READ_9";
            break;
        case C1222::RequestResponseCodes_PREADDEFAULT:
            service_vector += "Req:PARTIAL_READ_DEFAULT";
            break;
        case C1222::RequestResponseCodes_PREADOFFSET:
            service_vector += "Req:PARTIAL_READ_OFFSET";
            break;
        case C1222::RequestResponseCodes_FULLWRITE:
            service_vector += "Req:FULLWRITE";
            break;
        case C1222::RequestResponseCodes_PWRITEONE:
            service_vector += "Req:PARTIAL_PARTIAL_1";
            break;
        case C1222::RequestResponseCodes_PWRITETWO:
            service_vector += "Req:PARTIAL_PARTIAL_2";
            break;
        case C1222::RequestResponseCodes_PWRITETHREE:
            service_vector += "Req:PARTIAL_PARTIAL_3";
            break;
        case C1222::RequestResponseCodes_PWRITEFOUR:
            service_vector += "Req:PARTIAL_PARTIAL_4";
            break;
        case C1222::RequestResponseCodes_PWRITEFIVE:
            service_vector += "Req:PARTIAL_PARTIAL_5";
            break;
        case C1222::RequestResponseCodes_PWRITESIX:
            service_vector += "Req:PARTIAL_PARTIAL_6";
            break;
        case C1222::RequestResponseCodes_PWRITESEVEN:
            service_vector += "Req:PARTIAL_PARTIAL_7";
            break;
        case C1222::RequestResponseCodes_PWRITEEIGHT:
            service_vector += "Req:PARTIAL_PARTIAL_8";
            break;
        case C1222::RequestResponseCodes_PWRITENINE:
            service_vector += "Req:PARTIAL_PARTIAL_9";
            break;
        case C1222::RequestResponseCodes_PWRITEOFFSET:
            service_vector += "Req:PARTIAL_PARTIAL_OFFSET";
            break;
        case C1222::RequestResponseCodes_LOGON:
            service_vector += "Req:LOGON";
            break;
        case C1222::RequestResponseCodes_SECURITY:
            service_vector += "Req:SECURITY";
            break;
        case C1222::RequestResponseCodes_LOGOFF:
            service_vector += "Req:LOGOFF";
            break;
        case C1222::RequestResponseCodes_TERMINATE:
            service_vector += "Req:TERMINATE";
            break;
        case C1222::RequestResponseCodes_DISCONNECT:
            service_vector += "Req:DISCONNECT";
            break;
        case C1222::RequestResponseCodes_WAIT:
            service_vector += "Req:WAIT";
            break;
        case C1222::RequestResponseCodes_REGISTER:
            service_vector += "Req:REGISTER";
            break;
        case C1222::RequestResponseCodes_DEREGISTER:
            service_vector += "Req:DEREGISTER";
            break;
        case C1222::RequestResponseCodes_RESOLVE:
            service_vector += "Req:RESOLVE";
            break;
        case C1222::RequestResponseCodes_TRACE:
            service_vector += "Req:TRACE";
            break;
        default:
            service_vector += "Unknown Service";
            break;
        }
    }

    return service_vector;
}

event C1222::AscePdu(c: connection, is_orig: bool, ascepdu: Zeek_C1222::AscePdu) {
    hook set_session_summary_log(c);

    local info_summary_log = c$c1222_summary_log;

    #elements
    local element_vector: vector of string;

    for (i,element in ascepdu$elements){
        switch element$tag {
            case C1222::AsceElementTags_APPLICATION_CONTEXT:
                local ASOID = element$applicationContext$asoContext;
                info_summary_log$aso_context = getIdString(ASOID);
                element_vector += "Application_Context";
                break;
            case C1222::AsceElementTags_CALLED_AP_TITLE:
                local calledApTitle = element$calledApTitle$apTitle;
                info_summary_log$called_ap_title = getIdString(calledApTitle);
                element_vector += "Called_AP_Title";
                break;
            case C1222::AsceElementTags_CALLED_AP_INVOCATION_ID:
                info_summary_log$called_ap_invocation_id = element$calledApInvocationId$id;
                element_vector += "Called_AP_Invocation_ID";
                break;
            case C1222::AsceElementTags_CALLING_AP_TITLE:
                local callingApTitle = element$callingApTitle$apTitle;
                info_summary_log$calling_ap_title = getIdString(callingApTitle);
                element_vector += "Calling_AP_Title";
                break;
            case C1222::AsceElementTags_CALLING_APPLICATION_ENTITY_QUALIFIER:
                local qualifier_element: vector of string;
                local qualifier = element$callingApplicationEntityQualifier$callingAeQualifier;

                if(qualifier$TEST == T){
                    qualifier_element += "TEST";
                }
                if(qualifier$URGENT == T){
                    qualifier_element += "URGENT";
                }
                if(qualifier$NOTIFICATION == T){
                    qualifier_element += "NOTIFICATION";
                }
                if(qualifier?$RESERVED){
                    qualifier_element += fmt("RESERVED int:%s", qualifier$RESERVED);
                }

                info_summary_log$calling_ae_qualifier = qualifier_element;

                element_vector += "Calling_Application_Entity_Qualifier";
                break;
            case C1222::AsceElementTags_CALLING_AP_INVOCATION_ID:
                info_summary_log$calling_ap_invocation_id = element$callingApInvocationId$id;
                element_vector += "Calling_AP_Invocation_ID";
                break;
            case C1222::AsceElementTags_CALLING_AUTHENTICATION_VALUE:
                local authValueTag = element$callingAuthenticationValue$encodingTag;
                if(authValueTag == C1222::EncodingTags_OCTET){
                    info_summary_log$calling_auth_value = "OCTET_ALINGED";
                }
                else if (authValueTag == C1222::EncodingTags_ASN1){
                    local mechanismTag = element$callingAuthenticationValue$singleAsn1$mechanismTag;
                    if(mechanismTag == C1222::EncodingASN1Tags_C1222){
                        info_summary_log$calling_auth_value = "C12.22";
                    }
                    else if(mechanismTag == C1222::EncodingASN1Tags_C1221){
                        info_summary_log$calling_auth_value = "C12.21";
                    }
                    else{
                        info_summary_log$calling_auth_value = "UNIMPLEMENTED";
                    }
                }
                else{
                    info_summary_log$calling_auth_value = "UNKNOWN";
                }
                element_vector += "Calling_Authentication_Value";
                break;
            case C1222::AsceElementTags_MECHANISM_NAME:
                info_summary_log$mechanism_name = element$mechanismName$name$oidstring;
                element_vector += "Mechanism_Name";
                break;
            case C1222::AsceElementTags_USER_INFORMATION:
                element_vector += "User_Information";
                break;
            default:
                element_vector += "Unknown Element";
                break;
        }
    }

    info_summary_log$elements = element_vector;

    #encypted epsem
    local elementcount = |ascepdu$elements|;
    local securityMode = ascepdu$elements[elementcount -1]$userInformation$epsem$epsemControl$securityMode;

    if(securityMode == 2){
        info_summary_log$is_encrypted_epsem = T;
    }
    else{
        info_summary_log$is_encrypted_epsem = F;
    }

    #service codes
    if(ascepdu$elements[elementcount -1]$userInformation$epsem?$data){
        local services = ascepdu$elements[elementcount -1]$userInformation$epsem$data$data;
        local service_vector_log = getServiceVectorLog(services);

        info_summary_log$services = service_vector_log;
    }
    
}

event C1222::CallingAuthenticationValue(c: connection, is_orig: bool, callingauthenticationvalue: Zeek_C1222::CallingAuthenticationValue) {
	hook set_authentication_value_log(c);

    local auth_value_log = c$c1222_authentication_value_log;
    local auth_value = callingauthenticationvalue;

    #indirect ref
    if(auth_value$indirectReference?$c && auth_value$indirectReference$c == 0x00){
        auth_value_log$indirect_reference = T;
    }
    else{
        auth_value_log$indirect_reference = F;
    }

    #authentication_mechanism
    local authValueTag = auth_value$encodingTag;
    if(authValueTag == C1222::EncodingTags_OCTET){
        auth_value_log$authentication_mechanism = "OCTET_ALINGED";
        auth_value_log$octet_aligned = auth_value$octetAligned$octets;
    }
    else if (authValueTag == C1222::EncodingTags_ASN1){
        local mechanismTag = auth_value$singleAsn1$mechanismTag;
        if(mechanismTag == C1222::EncodingASN1Tags_C1222){
            auth_value_log$authentication_mechanism = "C12.22";
            auth_value_log$c1222_key_id = auth_value$singleAsn1$c1222Encoding$keyId$keyId;
            auth_value_log$c1222_iv = auth_value$singleAsn1$c1222Encoding$iv$iv;
        }
        else if(mechanismTag == C1222::EncodingASN1Tags_C1221){
            auth_value_log$authentication_mechanism = "C12.21";
            if(auth_value$singleAsn1$c1221Encoding$msg == C1222::EncodingC1221Tags_IDENT){
                auth_value_log$c1221_ident = auth_value$singleAsn1$c1221Encoding$authIdent$authService;
            }
            if(auth_value$singleAsn1$c1221Encoding$msg == C1222::EncodingC1221Tags_REQUEST){
                auth_value_log$c1221_req = auth_value$singleAsn1$c1221Encoding$authReq$authReq;
            }
            if(auth_value$singleAsn1$c1221Encoding$msg == C1222::EncodingC1221Tags_RESPONSE){
                auth_value_log$c1221_resp = auth_value$singleAsn1$c1221Encoding$authResp$authResp;
            }
        }
        else{
            auth_value_log$authentication_mechanism = "UNIMPLEMENTED";
        }
    }
    else{
        auth_value_log$authentication_mechanism = "UNKNOWN";
    }

}


event C1222::UserInformation(c: connection, is_orig: bool, userinformation: Zeek_C1222::UserInformation) {
    hook set_user_information_log(c);

    local user_info_log = c$c1222_user_information_log;
    local user_info_value = userinformation;

    if (user_info_value$indirectReference?$encoding) {
        user_info_log$indirect_reference_encoding = user_info_value$indirectReference$encoding;
    }

    user_info_log$padding = user_info_value$footer$padding;
    user_info_log$mac = user_info_value$footer$mac;
    user_info_log$epsem_control = user_info_value$epsem$epsemControl;

    #ed class
    local edClassIncluded = user_info_value$epsem$epsemControl$edClassIncluded;

    if (edClassIncluded == 1) {
        user_info_log$ed_class = user_info_value$epsem$edClass;
    }

    #encypted epsem or services
    local securityMode = user_info_value$epsem$epsemControl$securityMode;

    if(securityMode == 2) { # it is encrypted
        user_info_log$encrypted_epsem = user_info_value$epsem$encryptedEpsem;
        #user_info_log$services = ; # can't get services unless decrypted
    }
    else {
        local services = user_info_value$epsem$data$data;
        user_info_log$services = getServiceVectorLog(services);
    }
}

event C1222::Service(c: connection, is_orig: bool, serviceType: Zeek_C1222::Service){
    local service = serviceType$serviceTag;

    #Ident Req
    if(service == C1222::RequestResponseCodes_IDENT){
        hook set_identification_service_log(c);
        local ident_log = c$c1222_identification_service_log;
        ident_log$req_resp = "Req";
    }
}

event C1222::EndService(c: connection, is_orig: bool){
    C1222::emit_c1222_identification_service_log(c);
}

#Ident Resp
event C1222::ResponseOkIdent(c: connection, is_orig: bool, ident: Zeek_C1222::ResponseOkIdent) {
    hook set_identification_service_log(c);

    local ident_log = c$c1222_identification_service_log;
    ident_log$req_resp = "Resp";
    
    #std
    local std_tag = ident$std;
    switch std_tag {
        case 0x00:
            ident_log$standard = "ANSI C12.18";
            break;
        case 0x01:
            ident_log$standard = "RESERVED";
            break;
        case 0x02:
            ident_log$standard = "ANSI C12.21";
            break;
        case 0x03:
            ident_log$standard = "ANSI C12.22";
            break;
        default:
            ident_log$standard = "RESERVED";
            break;
    }

    #version
    ident_log$version = ident$ver;
    #revision
    ident_log$revision = ident$rev;

    #features
    for (i,feature in ident$features){
        local feature_tag = feature$tag;
        switch feature_tag {
            case C1222::IdentFeatureTags_SECURITY_MECHANISM:
                ident_log$security_mechanism = getIdString(feature$securityMechanism);
                break;
            case C1222::IdentFeatureTags_SESSION_CTRL:
                if(feature$sessionCtrl$sessionCtrl$nbrSessionSupported == 0){
                    ident_log$nbrSession_supported = F;
                }
                else{
                    ident_log$nbrSession_supported = T;
                }
                ident_log$sessionless_supported = feature$sessionCtrl$sessionCtrl$sessionlessSupported;
                break;
            case C1222::IdentFeatureTags_DEVICE_CLASS:
                ident_log$device_class = getIdString(feature$deviceClass);
                break;
            case C1222::IdentFeatureTags_DEVICE_IDENTITY:
                ident_log$device_identity_format = feature$deviceIdentity$format;
                ident_log$device_identity = feature$deviceIdentity$identification;
                break;                
        }
    }

}

event C1222::EndPacket(c: connection, is_orig: bool) {
    C1222::emit_c1222_summary_log(c);
    emit_c1222_authentication_value_log(c);
    emit_c1222_user_information_log(c);
}