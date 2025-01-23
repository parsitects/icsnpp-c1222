module C1222;

export {
    ## Record type containing the column fields of the summary c12.22 log.
    type summary_log: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        proto: transport_proto &log;

        elements: vector of string &optional &log;
        is_encrypted_epsem: bool &optional &log;
        services: vector of string &log &optional;

        aso_context: string &optional &log;
        called_ap_title: string &optional &log;
        calling_ap_title: string &optional &log;
        calling_ae_qualifier: vector of string &optional &log;
        mechanism_name: string &optional &log;
        calling_auth_value: string &optional &log; #will list the mechanism name. Details in another log.
        called_ap_invocation_id: string &optional &log;
        calling_ap_invocation_id: string &optional &log;
    };

    ## Record type containing the column fields of the summary c12.22 log.
    type authentication_value_log: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        proto: transport_proto &log;

        authentication_mechanism: string &optional &log;
        indirect_reference: bool &optional &log;
        octet_aligned: string &optional &log;
        c1222_key_id: int &optional &log;
        c1222_iv: int &optional &log;
        c1221_ident: string &optional &log;
        c1221_req: string &optional &log;
        c1221_resp: string &optional &log;
    };

    #user data
        #indirect reference encoding
        #mac
        #epsem control
        #ed class
        #encrypted epsem
        #services

    #Identification

    #Read

    #Write

    #Logon

    #Security

    #Logoff

    #Terminate

    #Disconnect

    #Wait

    #Registration

    #Deregistration

    #Trace


}