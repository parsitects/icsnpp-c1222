spicy-c1222
=================================

A Spicy protocol parser for for parsing C12.22 data.

```
$ zeek -C -r c1222overIPv4.cap local "C1222::c1222_ports_tcp = { 1153/tcp }" "C1222::c1222_ports_udp = { 1153/udp }"
```
