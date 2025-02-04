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

    type user_information_epsem_control_log : record {
        responseControl: count &optional;
        securityMode: count &optional;
        edClassIncluded: count &optional;
        proxyServiceUsed: count &optional;
        recoverySession: count &optional;
    };

    ## Record type containing the column fields of the summary c12.22 log.
    type user_information_log: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        proto: transport_proto &log;

        indirect_reference_encoding: int &optional &log;
        padding: string &optional &log;
        mac: string &optional &log;
        epsem_control: user_information_epsem_control_log &optional &log;
        ed_class: string &optional &log;
        encrypted_epsem: string &optional &log;
        services: vector of string &optional &log;
    };

    #Record type containing the column fields of the Identification service c12.22 log.
    type identification_service_log: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        proto: transport_proto &log;

        req_resp: string &optional &log;
        standard: string &optional &log;
        version: int &optional &log;
        revision: int &optional &log;
        security_mechanism: string &optional &log;
        nbrSession_supported: bool &optional &log;
        sessionless_supported: bool &optional &log;
        device_class: string &optional &log;
        device_identity_format: int &optional &log;
        device_identity: string &optional &log;
    };

    #Read/write
        #request/response
        #service type
        #tableid
        #offset
        #index
        #element count
        #count
        #data
        #cksum

    #Record type containing the column fields of the Logon service c12.22 log.
    type logon_service_log: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        proto: transport_proto &log;

        req_resp: string &optional &log;
        user_id: int &optional &log;
        user: string &optional &log;
        req_session_idle_timeout: int &optional &log;
        resp_session_idle_timeout: int &optional &log;
    };

    #Security
        #request/response
        #password
        #userid

    #Wait
        #request/response
        #time

    #Registration
        #request/response
        #node type
        #conneciton type
        #device class
        #ap title
        #electronic serial number
        #native address
        #registration period
        #notification pattern
        #reg-ap-title
        #reg-delay
        #reg-period
        #reg-info

    #Deregistration
        #request/response
        #ap title

    #resolve
        #request/response
        #ap title
        #local address

    #Trace
        #request/resposne
        #vector of aptitle

    #error
        #service
        #type


}