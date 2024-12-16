module C1222;

hook set_session_summary_log(c: connection) {
    if ( ! c?$c1222_summary_log )
        c$c1222_summary_log = summary_log(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto=get_conn_transport_proto(c$id));
}


event C1222::AscePdu(c: connection, is_orig: bool, ascepdu: Zeek_C1222::AscePdu) {
    hook set_session_summary_log(c);

    local info_summary_log = c$c1222_summary_log;

    #elements
    local element_vector: vector of string;

    for (i,element in ascepdu$elements){
        switch element$tag {
            case C1222::AsceElementTags_APPLICATION_CONTEXT:
#               info_summary_log$aso_context = element$applicationContext$asoContext$id$oidstring;
                element_vector += "Application_Context";
                break;
            case C1222::AsceElementTags_CALLED_AP_TITLE:
#                local calledApTitleTag = element$calledApTitle$apTitleTag;
#                switch calledApTitleTag {
#                    case C1222::IdentifierTags_UNIVERSAL:
#                        info_summary_log$called_ap_title = element$calledApTitle$universalAptitleId$id$oidstring;
#                        break;
#                    case C1222::IdentifierTags_RELATIVE:
#                        info_summary_log$called_ap_title = element$calledApTitle$relativeAptitleId$id$oidstring;
#                        break;
#                }
                element_vector += "Called_AP_Title";
                break;
            case C1222::AsceElementTags_CALLED_AP_INVOCATION_ID:
                element_vector += "Called_AP_Invocation_ID";
                break;
            case C1222::AsceElementTags_CALLING_AP_TITLE:
 #               local callingApTitleTag = element$callingApTitle$apTitleTag;
 #               switch callingApTitleTag {
 #                   case C1222::IdentifierTags_UNIVERSAL:
 #                       info_summary_log$calling_ap_title = element$callingApTitle$universalAptitleId$id$oidstring;
 #                       break;
 #                   case C1222::IdentifierTags_RELATIVE:
 #                       info_summary_log$calling_ap_title = element$callingApTitle$relativeAptitleId$id$oidstring;
 #                       break;
 #               }
                element_vector += "Calling_AP_Title";
                break;
            case C1222::AsceElementTags_CALLING_APPLICATION_ENTITY_QUALIFIER:
                element_vector += "Calling_Application_Entity_Qualifier";
                break;
            case C1222::AsceElementTags_CALLING_AP_INVOCATION_ID:
                element_vector += "Calling_AP_Invocation_ID";
                break;
            case C1222::AsceElementTags_CALLING_AUTHENTICATION_VALUE:
                element_vector += "Calling_Authentication_Value";
                break;
            case C1222::AsceElementTags_MECHANISM_NAME:
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
        local service_vector: vector of string;

        
        for(i,item in ascepdu$elements[elementcount -1]$userInformation$epsem$data$data){

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

        info_summary_log$services = service_vector;
    }
    

    C1222::emit_c1222_summary_log(c);
}

event C1222::CallingAuthenticationValue(c: connection, is_orig: bool, callingauthenticationvalue: Zeek_C1222::CallingAuthenticationValue) {
	;
}


event C1222::UserInformation(c: connection, is_orig: bool, userinformation: Zeek_C1222::UserInformation) {
	;
}