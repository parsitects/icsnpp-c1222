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

hook set_read_write_service_log(c: connection) {
    if (! c?$c1222_read_write_service_log)
        c$c1222_read_write_service_log = read_write_service_log(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto=get_conn_transport_proto(c$id));
}

hook set_logon_service_log(c: connection) {
    if (! c?$c1222_logon_service_log)
        c$c1222_logon_service_log = logon_service_log(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto=get_conn_transport_proto(c$id));
}

hook set_security_service_log(c: connection) {
    if (! c?$c1222_security_service_log)
        c$c1222_security_service_log = security_service_log(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto=get_conn_transport_proto(c$id));
}

hook set_service_error_log(c: connection) {
    if (! c?$c1222_service_error_log)
        c$c1222_service_error_log = service_error_log(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto=get_conn_transport_proto(c$id));
}

function getIdString(ID: Zeek_C1222::ID): string{
    local tag = ID$tag;
    local returnVal: string;
    switch tag {
        case C1222_ENUMS::IdentifierTags_UNIVERSAL:
            returnVal = ID$universalAptitleId$oidstring;
            break;
        case C1222_ENUMS::IdentifierTags_RELATIVE:
            returnVal = ID$relativeAptitleId$oidstring;
            break;
    }
    return returnVal;
}

function getServiceVectorLog(services: vector of Zeek_C1222::EpsemService): vector of string {
    local service_vector: vector of string;

    for (i, item in services) {
        service_vector += C1222_ENUMS::REQUEST_RESPONSE_CODES[item$service$serviceTag];
    }

    return service_vector;
}

event C1222::AscePdu(c: connection, is_orig: bool, ascepdu: Zeek_C1222::AscePdu) {
    hook set_session_summary_log(c);

    local info_summary_log = c$c1222_summary_log;

    #elements
    local element_vector: vector of string;

    for (i,element in ascepdu$elements){

        element_vector += C1222_ENUMS::ASCE_ELEMENT_TAGS[element$tag];

        switch element$tag {
            case C1222_ENUMS::AsceElementTags_APPLICATION_CONTEXT:
                local ASOID = element$applicationContext$asoContext;
                info_summary_log$aso_context = getIdString(ASOID);
                break;
            case C1222_ENUMS::AsceElementTags_CALLED_AP_TITLE:
                local calledApTitle = element$calledApTitle$apTitle;
                info_summary_log$called_ap_title = getIdString(calledApTitle);
                break;
            case C1222_ENUMS::AsceElementTags_CALLED_AP_INVOCATION_ID:
                info_summary_log$called_ap_invocation_id = element$calledApInvocationId$id;
                break;
            case C1222_ENUMS::AsceElementTags_CALLING_AP_TITLE:
                local callingApTitle = element$callingApTitle$apTitle;
                info_summary_log$calling_ap_title = getIdString(callingApTitle);
                break;
            case C1222_ENUMS::AsceElementTags_CALLING_APPLICATION_ENTITY_QUALIFIER:
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

                break;
            case C1222_ENUMS::AsceElementTags_CALLING_AP_INVOCATION_ID:
                info_summary_log$calling_ap_invocation_id = element$callingApInvocationId$id;
                break;
            case C1222_ENUMS::AsceElementTags_CALLING_AUTHENTICATION_VALUE:
                local authValueTag = element$callingAuthenticationValue$encodingTag;
                info_summary_log$calling_auth_value = C1222_ENUMS::ENCODING_TAGS[authValueTag];
                if (authValueTag == C1222_ENUMS::EncodingTags_ASN1){
                    local mechanismTag = element$callingAuthenticationValue$singleAsn1$mechanismTag;
                    info_summary_log$calling_auth_value = C1222_ENUMS::ENCODING_ASN1_TAGS[mechanismTag];
                }
                break;
            case C1222_ENUMS::AsceElementTags_MECHANISM_NAME:
                info_summary_log$mechanism_name = element$mechanismName$name$oidstring;
                break;
            default:
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
    if(authValueTag == C1222_ENUMS::EncodingTags_OCTET){
        auth_value_log$authentication_mechanism = "OCTET_ALINGED";
        auth_value_log$octet_aligned = auth_value$octetAligned$octets;
    }
    else if (authValueTag == C1222_ENUMS::EncodingTags_ASN1){
        local mechanismTag = auth_value$singleAsn1$mechanismTag;
        if(mechanismTag == C1222_ENUMS::EncodingASN1Tags_C1222){
            auth_value_log$authentication_mechanism = "C12.22";
            auth_value_log$c1222_key_id = auth_value$singleAsn1$c1222Encoding$keyId$keyId;
            auth_value_log$c1222_iv = auth_value$singleAsn1$c1222Encoding$iv$iv;
        }
        else if(mechanismTag == C1222_ENUMS::EncodingASN1Tags_C1221){
            auth_value_log$authentication_mechanism = "C12.21";
            if(auth_value$singleAsn1$c1221Encoding$msg == C1222_ENUMS::EncodingC1221Tags_IDENT){
                auth_value_log$c1221_ident = auth_value$singleAsn1$c1221Encoding$authIdent$authService;
            }
            if(auth_value$singleAsn1$c1221Encoding$msg == C1222_ENUMS::EncodingC1221Tags_REQUEST){
                auth_value_log$c1221_req = auth_value$singleAsn1$c1221Encoding$authReq$authReq;
            }
            if(auth_value$singleAsn1$c1221Encoding$msg == C1222_ENUMS::EncodingC1221Tags_RESPONSE){
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

    local read_write_log = c$c1222_read_write_service_log;

    #Ident Req
    if(service == C1222_ENUMS::RequestResponseCodes_IDENT){
        hook set_identification_service_log(c);
        local ident_log = c$c1222_identification_service_log;
        ident_log$req_resp = "Req";
    }
    # This part needs fixed (can't handle resp)...
    #else if(service == C1222::RequestResponseCodes_SECURITY){
        #hook set_security_service_log(c);
        #local security_log = c$c1222_security_service_log;
        #security_log$req_resp = "Resp";
    #}
    else if(service == C1222_ENUMS::RequestResponseCodes_PREADDEFAULT){
        hook set_read_write_service_log(c);
        read_write_log$req_resp = "Req";
        read_write_log$service_type = "pread-default";
    }
    else if(service == C1222_ENUMS::RequestResponseCodes_FULLREAD){
        hook set_read_write_service_log(c);
        read_write_log$req_resp = "Req";
        read_write_log$service_type = "full-read";
        read_write_log$table_id = serviceType$fullread;
    }
}

event C1222::EndService(c: connection, is_orig: bool){
    C1222::emit_c1222_identification_service_log(c);
    C1222::emit_c1222_read_write_service_log(c);
    C1222::emit_c1222_logon_service_log(c);
    C1222::emit_c1222_security_service_log(c);
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
            case C1222_ENUMS::IdentFeatureTags_SECURITY_MECHANISM:
                ident_log$security_mechanism = getIdString(feature$securityMechanism);
                break;
            case C1222_ENUMS::IdentFeatureTags_SESSION_CTRL:
                if(feature$sessionCtrl$sessionCtrl$nbrSessionSupported == 0){
                    ident_log$nbrSession_supported = F;
                }
                else{
                    ident_log$nbrSession_supported = T;
                }
                ident_log$sessionless_supported = feature$sessionCtrl$sessionCtrl$sessionlessSupported;
                break;
            case C1222_ENUMS::IdentFeatureTags_DEVICE_CLASS:
                ident_log$device_class = getIdString(feature$deviceClass);
                break;
            case C1222_ENUMS::IdentFeatureTags_DEVICE_IDENTITY:
                ident_log$device_identity_format = feature$deviceIdentity$format;
                ident_log$device_identity = feature$deviceIdentity$identification;
                break;                
        }
    }

}

#Logon Req
event C1222::LogonReq(c: connection, is_orig: bool, req: Zeek_C1222::LogonReq) {
    hook set_logon_service_log(c);

    local logon_log = c$c1222_logon_service_log;
    logon_log$req_resp = "Req";
    logon_log$user_id = req$userid;
    logon_log$user = req$user;
    logon_log$req_session_idle_timeout = req$reqSessionTimeout;
}

#Logon Resp
event C1222::LogonResp(c: connection, is_orig: bool, resp: Zeek_C1222::LogonResp) {
    hook set_logon_service_log(c);

    local logon_log = c$c1222_logon_service_log;
    logon_log$req_resp = "Resp";
    logon_log$resp_session_idle_timeout = resp$respSessionTimeout;
}

#Security Req
event C1222::SecurityReq(c: connection, is_orig: bool, req: Zeek_C1222::SecurityReq) {
    hook set_security_service_log(c);

    local security_log = c$c1222_security_service_log;
    security_log$req_resp = "Req";
    security_log$password = req$password;
    security_log$user_id = req$userid;
}

# READ / WRITE SERVICE EVENTS -------------------------------------------------------------

#ReadReqPRead
event C1222::ReadReqPRead(c: connection, is_orig: bool, req: Zeek_C1222::ReadReqPRead) {
    hook set_read_write_service_log(c);

    local read_write_log = c$c1222_read_write_service_log;
    read_write_log$req_resp = "Req";
    read_write_log$service_type = "pread";
    read_write_log$table_id = req$tableid;

    # Display indices with decimals in between, ex: 3.1.1
    for (i,indexN in req$index) {
        if (i > 0) {
            read_write_log$index += ".";
        }

        read_write_log$index += cat(indexN);
    }

    read_write_log$element_count = req$elementCount;
}

#ReadReqPReadOffset
event C1222::ReadReqPReadOffset(c: connection, is_orig: bool, req: Zeek_C1222::ReadReqPReadOffset) {
    hook set_read_write_service_log(c);

    local read_write_log = c$c1222_read_write_service_log;
    read_write_log$req_resp = "Req";
    read_write_log$service_type = "pread-offset";
    read_write_log$table_id = req$tableid;
    read_write_log$offset = bytestring_to_count(req$offset);
    read_write_log$octet_count = req$octetCount;
}

#ReadRespOk
event C1222::ReadRespOk(c: connection, is_orig: bool, resp: Zeek_C1222::ReadRespOk) {
    hook set_read_write_service_log(c);

    local read_write_log = c$c1222_read_write_service_log;
    read_write_log$req_resp = "Resp";
    read_write_log$service_type = "readresp-ok";

    for (i,tableM in resp$tables) {
        read_write_log$count_m += tableM$count_m;
        read_write_log$data += tableM$data;
        read_write_log$chksum += tableM$cksum;
    }

    for (i,extraTable in resp$extratables) {
        read_write_log$count_m += extraTable$count_m;
        read_write_log$data += extraTable$data;
        read_write_log$chksum += extraTable$cksum;
    }
}

#WriteReqFull
event C1222::WriteReqFull(c: connection, is_orig: bool, req: Zeek_C1222::WriteReqFull) {
    hook set_read_write_service_log(c);

    local read_write_log = c$c1222_read_write_service_log;
    read_write_log$req_resp = "Req";
    read_write_log$service_type = "full-write";
    read_write_log$table_id = req$tableid;

    local tableVal = req$table_m;
    read_write_log$count_m += tableVal$count_m;
    read_write_log$data += tableVal$data;
    read_write_log$chksum += tableVal$cksum;

    if (tableVal$count_m == 0xFFFF) { # extra table is valid
        local extraTable = req$extra;

        read_write_log$count_m += extraTable$count_m;
        read_write_log$data += extraTable$data;
        read_write_log$chksum += extraTable$cksum; # TODO: Is adding the checksum acceptable here?
    }
}

#WriteReqPWrite
event C1222::WriteReqPWrite(c: connection, is_orig: bool, req: Zeek_C1222::WriteReqPWrite) {
    hook set_read_write_service_log(c);

    local read_write_log = c$c1222_read_write_service_log;
    read_write_log$req_resp = "Req";
    read_write_log$service_type = "pwrite";
    read_write_log$table_id = req$tableid;

    # Display indices with decimals in between, ex: 3.1.1
    for (i,indexN in req$index) {
        if (i > 0) {
            read_write_log$index += ".";
        }

        read_write_log$index += cat(indexN);
    }

    local tableVal = req$table_m;
    read_write_log$count_m += tableVal$count_m;
    read_write_log$data += tableVal$data;
    read_write_log$chksum += tableVal$cksum;
}

#WriteReqOffset
event C1222::WriteReqOffset(c: connection, is_orig: bool, req: Zeek_C1222::WriteReqOffset) {
    hook set_read_write_service_log(c);

    local read_write_log = c$c1222_read_write_service_log;
    read_write_log$req_resp = "Req";
    read_write_log$service_type = "pwrite-offset";
    read_write_log$table_id = req$tableid;
    read_write_log$offset = bytestring_to_count(req$offset); 
    
    local tableVal = req$table_m;
    read_write_log$count_m += tableVal$count_m;
    read_write_log$data += tableVal$data;
    read_write_log$chksum += tableVal$cksum;
}

# ------------------------------------------------------------------------------

#Error Resp
event C1222::ResponseNok(c: connection, is_orig: bool, error_record: Zeek_C1222::ResponseNok) {
    hook set_service_error_log(c);

    local error_log = c$c1222_service_error_log;
    error_log$service = C1222_ENUMS::REQUEST_RESPONSE_CODES[error_record$command];
    error_log$error_code = C1222_ENUMS::REQUEST_RESPONSE_CODES[error_record$code_zeek];
    if(error_record?$maxRequestSize){
        error_log$rqtl_max_request_size = error_record$maxRequestSize;
    }
    if(error_record?$maxResponseSize){
        error_log$rstl_max_response_size = error_record$maxResponseSize;
    }
    if(error_record?$sigerrResp){
        error_log$sigerr_resp = error_record$sigerrResp;
    }

    #TODO: Add scripting to handle trace log on error
}

#END PACKET
event C1222::EndPacket(c: connection, is_orig: bool) {
    C1222::emit_c1222_summary_log(c);
    emit_c1222_authentication_value_log(c);
    emit_c1222_user_information_log(c);
    emit_c1222_service_error_log(c);
}