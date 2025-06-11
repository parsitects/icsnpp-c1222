# @TEST-EXEC: touch c1222.log
# @TEST-EXEC: touch c1222_user_information.log
# @TEST-EXEC: touch c1222_logon_service.log
#
# @TEST-EXEC: zeek -C -r ${TRACES}/c1222_security_service_tcp.pcap ${PACKAGE} %INPUT C1222::log_authentication_value=T C1222::log_identification_service=T C1222::log_read_write_service=T C1222::log_logon_service=T C1222::log_dereg_reg_service=T C1222::log_resolve_service=T C1222::log_trace_service=T
#
# @TEST-EXEC: zeek-cut -n ts uid < c1222.log > log.tmp && mv log.tmp c1222.log
# @TEST-EXEC: zeek-cut -n ts uid < c1222_user_information.log > log.tmp && mv log.tmp c1222_user_information.log
# @TEST-EXEC: zeek-cut -n ts uid < c1222_logon_service.log > log.tmp && mv log.tmp c1222_logon_service.log
#
# @TEST-EXEC: btest-diff c1222.log
# @TEST-EXEC: btest-diff c1222_user_information.log
# @TEST-EXEC: btest-diff c1222_logon_service.log
#
# @TEST-DOC: Test C12.22 analyzer with c1222_security_service_tcp.pcap