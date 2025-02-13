@load base/protocols/conn/removal-hooks

module C1222;

export {
	## Log stream identifier.
	redef enum Log::ID += { 
							LOG_SUMMARY_LOG,
              LOG_AUTHENTICATION_VALUE_LOG,
              LOG_USER_INFORMATION_LOG,
              LOG_IDENTIFICATION_SERVICE_LOG,
              LOG_READ_WRITE_SERVICE_LOG,
              LOG_LOGON_SERVICE_LOG,
              LOG_SECURITY_SERVICE_LOG
						  };


  global log_c1222: event(rec: summary_log);
  global log_policy_summary_log: Log::PolicyHook;
  global log_authentication_value_log: event(rec: authentication_value_log);
	global log_policy_authentication_value_log: Log::PolicyHook;
  global log_user_information_log: event(rec: user_information_log);
	global log_policy_user_information_log: Log::PolicyHook;
  global log_identification_service_log: event(rec: identification_service_log);
  global log_policy_identification_service_log: Log::PolicyHook;
  global log_read_write_service_log: event(rec: read_write_service_log);
  global log_policy_read_write_service_log: Log::PolicyHook;
  global log_logon_service_log: event(rec: logon_service_log);
  global log_policy_logon_service_log: Log::PolicyHook;
  global log_security_service_log: event(rec: security_service_log);
  global log_policy_security_service_log: Log::PolicyHook;
}

redef record connection += {
	c1222_proto: string &optional;
	c1222_summary_log: summary_log &optional;
  c1222_authentication_value_log: authentication_value_log &optional;
  c1222_user_information_log: user_information_log &optional;
  c1222_identification_service_log: identification_service_log &optional;
  c1222_read_write_service_log: read_write_service_log &optional;
  c1222_logon_service_log: logon_service_log &optional;
  c1222_security_service_log: security_service_log &optional;
};

export {
    const c1222_ports_tcp: set[port] = { 1153/tcp } &redef;
    const c1222_ports_udp: set[port] = { 1153/udp } &redef;
}
redef likely_server_ports += { c1222_ports_tcp, c1222_ports_udp };

event zeek_init() &priority=5 {
	Analyzer::register_for_ports(Analyzer::ANALYZER_C1222_TCP, c1222_ports_tcp);
  Analyzer::register_for_ports(Analyzer::ANALYZER_C1222_UDP, c1222_ports_udp);

	Log::create_stream(C1222::LOG_SUMMARY_LOG, 
						[$columns=summary_log, 
						$ev=log_c1222, 
						$path="c1222", 
						$policy=log_policy_summary_log]);

	Log::create_stream(C1222::LOG_AUTHENTICATION_VALUE_LOG, 
						[$columns=authentication_value_log, 
						$ev=log_authentication_value_log, 
						$path="c1222_authentication_value", 
						$policy=log_policy_authentication_value_log]);

  Log::create_stream(C1222::LOG_USER_INFORMATION_LOG, 
						[$columns=user_information_log, 
						$ev=log_user_information_log, 
						$path="c1222_user_information", 
						$policy=log_policy_user_information_log]);

  Log::create_stream(C1222::LOG_IDENTIFICATION_SERVICE_LOG, 
						[$columns=identification_service_log, 
						$ev=log_identification_service_log, 
						$path="c1222_identification_service", 
						$policy=log_policy_identification_service_log]);

  Log::create_stream(C1222::LOG_READ_WRITE_SERVICE_LOG, 
						[$columns=read_write_service_log, 
						$ev=log_read_write_service_log, 
						$path="c1222_read_write_service", 
						$policy=log_policy_read_write_service_log]);

  Log::create_stream(C1222::LOG_LOGON_SERVICE_LOG, 
						[$columns=logon_service_log, 
						$ev=log_logon_service_log, 
						$path="c1222_logon_service", 
						$policy=log_policy_logon_service_log]);

  Log::create_stream(C1222::LOG_SECURITY_SERVICE_LOG, 
						[$columns=security_service_log, 
						$ev=log_security_service_log, 
						$path="c1222_security_service", 
						$policy=log_policy_security_service_log]);
}


@if (Version::at_least("5.2.2"))
event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo) {
  if ( atype == Analyzer::ANALYZER_C1222_TCP ) {
    info$c$c1222_proto = "tcp";
  } else if ( atype == Analyzer::ANALYZER_C1222_UDP ) {
    info$c$c1222_proto = "udp";
  }
}
@else
event analyzer_confirmation(c: connection, atype: Analyzer::Tag, aid: count) &priority=5 {
  if ( atype == Analyzer::ANALYZER_C1222_TCP ) {
    c$c1222_proto = "tcp";
  } else if ( atype == Analyzer::ANALYZER_C1222_UDP ) {
    c$c1222_proto = "udp";
  }
}
@endif


function emit_c1222_summary_log(c: connection) {
    if (! c?$c1222_summary_log )
        return;
    Log::write(C1222::LOG_SUMMARY_LOG, c$c1222_summary_log);
    delete c$c1222_summary_log;
}

function emit_c1222_authentication_value_log(c: connection) {
    if (! c?$c1222_authentication_value_log )
        return;
    Log::write(C1222::LOG_AUTHENTICATION_VALUE_LOG, c$c1222_authentication_value_log);
    delete c$c1222_authentication_value_log;
}

function emit_c1222_user_information_log(c: connection) {
    if (! c?$c1222_user_information_log )
        return;
    Log::write(C1222::LOG_USER_INFORMATION_LOG, c$c1222_user_information_log);
    delete c$c1222_user_information_log;
}

function emit_c1222_identification_service_log(c: connection) {
    if (! c?$c1222_identification_service_log )
        return;
    Log::write(C1222::LOG_IDENTIFICATION_SERVICE_LOG, c?$c1222_identification_service_log);
    delete c$c1222_identification_service_log;
}

function emit_c1222_read_write_service_log(c: connection) {
    if (! c?$c1222_read_write_service_log )
        return;
    Log::write(C1222::LOG_READ_WRITE_SERVICE_LOG, c?$c1222_read_write_service_log);
    delete c$c1222_read_write_service_log;
}

function emit_c1222_logon_service_log(c: connection) {
    if (! c?$c1222_logon_service_log )
        return;
    Log::write(C1222::LOG_LOGON_SERVICE_LOG, c?$c1222_logon_service_log);
    delete c$c1222_logon_service_log;
}

function emit_c1222_security_service_log(c: connection) {
    if (! c?$c1222_security_service_log )
        return;
    Log::write(C1222::LOG_SECURITY_SERVICE_LOG, c?$c1222_security_service_log);
    delete c$c1222_security_service_log;
}