# ICSNPP-C12.22

Industrial Control Systems Network Protocol Parsers (ICSNPP) - ANSI C12.22 for  over TCP and UDP.

## Overview

ICSNPP-C12.22 is a Zeek plugin (written in [Spicy](https://docs.zeek.org/projects/spicy/en/latest/)) for parsing and logging fields used by the ANSI C12.22 protocol as presented in IEEE standard 1703-2012, defining a transmission format for utility end device data tables or control elements.

This parser produces the following log files, defined in [analyzer/main.zeek](analyzer/main.zeek):

* `c1222.log`
* `c1222_authentication_value.log`
* `c1222_user_information.log`
* `c1222_identification_service.log`
* `c1222_read_write_service.log`
* `c1222_logon_service.log`
* `c1222_security_service.log`
* `c1222_wait_service.log`
* `c1222_dereg_reg_service.log`
* `c1222_resolve_service.log`
* `c1222_trace_service.log`
* `c1222_service_error.log`

For additional information on this log file, see the *Logging Capabilities* section below.

## Installation

### Package Manager

This script is available as a package for [Zeek Package Manager](https://docs.zeek.org/projects/package-manager/en/stable/index.html). It requires [Spicy](https://docs.zeek.org/projects/spicy/en/latest/) and the [Zeek Spicy plugin](https://docs.zeek.org/projects/spicy/en/latest/zeek.html).

```bash
$ zkg refresh
$ zkg install icsnpp-c1222
```


If this package is installed from ZKG, it will be added to the available plugins. This can be tested by running `zeek -NN`. If installed correctly, users will see `ANALYZER_SPICY_C1222_TCP` and `ANALYZER_SPICY_C1222_UDP` under the list of `Zeek::Spicy` analyzers.

If users have ZKG configured to load packages (see `@load packages` in the [ZKG Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)), this plugin and these scripts will automatically be loaded and ready to go.

## Logging Capabilities

### C12.22 Summary Log (c1222.log)

#### Overview

This log summarizes, by packet, ANSI C12.22 frames transmitted over 1153/tcp or 1153/udp to `c1222.log`. The port can be overriden by redefining the `c1222_ports_tcp` and `c1222_ports_udp` variables, respectively, e.g.:

```
$ zeek -C -r c1222_tcp.pcap local "C1222::c1222_ports_tcp={ 40712/tcp }"
```

#### Fields Captured

| Field                     | Type           | Description                                               |
| --------------------------|----------------|-----------------------------------------------------------| 
| ts                        | time           | Timestamp (network time)                                  |
| uid                       | string         | Unique ID for this connection                             |
| id                        | conn_id        | Default Zeek connection info (IP addresses, ports)        |
| proto                     | string         | Transport protocol                                        |
| elements                  | set<string>    | List of the ASCE Elements utilized in the packet          |
| is_encrypted_epsem        | bool           | Flag denoting if the EPSEM data is encrypted              |
| services                  | set<string>    | List of epsem services in the packet                      |
| aso_context               | string         | Application context universal identifier                  |
| called_ap_title           | string         | Unique identifier of message target                       |
| calling_ap_title          | string         | Unique identifier of message initiator                    |
| calling_ae_qualifier      | set<string>    | Qualifies data being sent                                 |
| mechanism name            | string         | Unique security mechanism identifier                      |
| calling_auth_value        | string         | Authenticatin mechanism used                              |
| called_ap_invocation_id   | string         | Called AP invocation identifier                           |
| calling_ap_invocation_id  | string         | Calling AP invocation identifier                          |

* The **`calling_ae_qualifer`** field is comprised of four non-exclusive qualifiers:
    - `TEST` - test message
    - `URGENT` - high priority message
    - `NOTIFICATION` - write services issued as a notification
    - `RESERVED` - a reserved bit is set
* The **`calling_auth_value`** field contains a summary of the authentication mechanism used. Details of the calling 
authentication value can be found in `c1222_authentication_value.log`.

### Authentication Value Log (c1222_authentication_value.log)

#### Overview

This log provides the values used for the authentication method in the message.

#### Fields Captured

| Field                     | Type           | Description                                               |
| --------------------------|----------------|-----------------------------------------------------------|
| ts                        | time           | Timestamp (network time)                                  |
| uid                       | string         | Unique ID for this connection                             |
| id                        | conn_id        | Default Zeek connection info (IP addresses, ports)        |
| proto                     | string         | Transport protocol                                        |
| authentication_mechanism  | string         | Authenticatin mechanism used                              |
| indirect_reference        | bool           | Indirect reference bytes present                          |
| octet_aligned             | string         | Bytes used to define octet aligned authentication         |
| c1222_key_id              | int            | C12.22 auth key identifier                                |
| c1222_iv                  | string         | C12.22 auth initial value                                 |
| c1221_ident               | string         | C12.21 auth identification type                           |
| c1221_req                 | string         | C12.21 auth request type                                  |
| c1221_resp                | string         | C12.21 auth response type                                 |

### User Information Element Summary Log (c1222_user_information.log)

#### Overview

This log summarizes the User Information Element and the EPSEM data.

#### Fields Captured

| Field             | Type           | Description                                               |
| ----------------- |----------------|-----------------------------------------------------------|
| ts                | time           | Timestamp (network time)                                  |
| uid               | string         | Unique ID for this connection                             |
| id                | conn_id        | Default Zeek connection info (IP addresses, ports)        |
| proto             | string         | Transport protocol                                        |
| frame_type        | string         | Frame type from synchrophasor frame synchronization word  |
| frame_size        | count          | Frame size (in bytes)                                     |
| header_time_stamp | time           | Timestamp from frame header                               |
| command           | string         | String representation of the command                      |
| data              | string         | Human-readable header data (user-defined)                 |

### Identification Service Log (c1222_identification_service.log)

#### Overview

This log provides details of each data field in the Identification EPSEM service.

#### Fields Captured

| Field                  | Type           | Description                                               |
| -----------------------|----------------|-----------------------------------------------------------|
| ts                     | time           | Timestamp (network time)                                  |
| uid                    | string         | Unique ID for this connection                             |
| id                     | conn_id        | Default Zeek connection info (IP addresses, ports)        |
| proto                  | string         | Transport protocol                                        |
| req_resp               | string         | Request/Response                                          |
| standard               | string         | Reference Standard                                        |
| version                | int            | Reference Version Number                                  |
| revision               | int            | Reference Revision Number                                 |
| security_mechanism     | string         | Universal ID of the security mechanism supported          |
| nbrSession_supported   | bool           | Node supports session-based communication                 |
| sessionless_supported  | bool           | Supports use of read and write outside of session         |
| device_class           | string         | Universal device identifier                               |
| device_identity_format | int            | Device identity encoding format flag                      |
| device_identity        | string         | Device identity bytes                                     |

### Read Write Service Log (c1222_read_write_service.log)

#### Overview

This log provides details of each data field in the Read/Write EPSEM services.

#### Fields Captured

| Field                  | Type             | Description                                               |
| -----------------------|------------------|-----------------------------------------------------------|
| ts                     | time             | Timestamp (network time)                                  |
| uid                    | string           | Unique ID for this connection                             |
| id                     | conn_id          | Default Zeek connection info (IP addresses, ports)        |
| proto                  | string           | Transport protocol                                        |
| req_resp               | string           | Request/Response                                          |
| service_type           | string           | Name of the EPSEM service represented                     |
| table_id               | int              | ID of the table being read/written                        |
| offset                 | count            | Offset into data Table in bytes                           |
| index                  | string           | Index value used to locate start of data                  |
| element_count          | int              | Number of Table Elements to read/write                    |
| count_m                | vector of int    | Length of data written\returned                           |
| data                   | vector of string | Table data elements                                       |
| chksum                 | vector of int    | Checksum of each table                                    |
| octet_count            | int              | Length of Table data requested starting at offset         |

### Logon Service Log (c1222_logon_service.log)

#### Overview

This log provides details of each data field in the Logon EPSEM service.

#### Fields Captured

| Field                     | Type             | Description                                                |
| --------------------------|------------------|------------------------------------------------------------|
| ts                        | time             | Timestamp (network time)                                   |
| uid                       | string           | Unique ID for this connection                              |
| id                        | conn_id          | Default Zeek connection info (IP addresses, ports)         |
| proto                     | string           | Transport protocol                                         |
| req_resp                  | string           | Request/Response                                           |
| user_id                   | int              | User identification code                                   |
| user                      | string           | 10 bytes containing user identification                    |
| req_session_idle_timeout  | int              | Number of seconds a session may be idle before termination |
| resp_session_idle_timeout | int              | Number of seconds a session may be idle before termination |

### Security Service Log (c1222_security_service.log)

#### Overview

This log provides details of each data field in the Security EPSEM service.

#### Fields Captured

| Field                  | Type             | Description                                               |
| -----------------------|------------------|-----------------------------------------------------------|
| ts                     | time             | Timestamp (network time)                                  |
| uid                    | string           | Unique ID for this connection                             |
| id                     | conn_id          | Default Zeek connection info (IP addresses, ports)        |
| proto                  | string           | Transport protocol                                        |
| req_resp               | string           | Request/Response                                          |
| password               | string           | 20 byte field containing password                         |
| user_id                | int              | User identification code                                  |

### Wait Service Log (c1222_wait_service.log)

#### Overview

This log provides details of each data field in the Wait EPSEM service.

#### Fields Captured

| Field                  | Type             | Description                                               |
| -----------------------|------------------|-----------------------------------------------------------|
| ts                     | time             | Timestamp (network time)                                  |
| uid                    | string           | Unique ID for this connection                             |
| id                     | conn_id          | Default Zeek connection info (IP addresses, ports)        |
| proto                  | string           | Transport protocol                                        |
| req_resp               | string           | Request/Response                                          |
| time_s                 | int              | Requested wait period in seconds                          |

### Deregistration Registration Service Log (c1222_dereg_reg_service.log)

#### Overview

This log provides details of each data field in the Deregistration and Registration EPSEM services.

#### Fields Captured

| Field                     | Type             | Description                                                              |
| --------------------------|------------------|--------------------------------------------------------------------------|
| ts                        | time             | Timestamp (network time)                                                 |
| uid                       | string           | Unique ID for this connection                                            |
| id                        | conn_id          | Default Zeek connection info (IP addresses, ports)                       |
| proto                     | string           | Transport protocol                                                       |
| req_resp                  | string           | Request/Response                                                         |
| service_type              | string           | Name of the EPSEM service represented                                    |
| node_type                 | vector of string | An identification of the C12.22 Node’s Attributes                        |
| connection_type           | vector of string | An indication of the type of connection requested                        |
| device_class              | string           | Device Class                                                             |
| ap_title                  | string           | ApTitle of the C12.22 Node to be registered                              |
| electronic_serial_number  | string           | Unique ISO object identifier assigned to this Device                     |
| native_address            | string           | Native address to use to forward messages to this node                   |
| notification_pattern      | string           | An ApTitle associated with the Node-population                           |
| reg_period                | count            | Max period in seconds desired to elapse between re-registration requests |
| reg_delay                 | int              | Max delay in seconds the deviceshould wait before registering            |
| reg_info                  | vector of string | Registration Info                                                        |

* The **`node_type`** field identifies a node's attributes:
    - `RELAY` - Node is a C12.22 Relay
    - `MASTER_RELAY` -  Node is a C12.22 Master Relay
    - `HOST` - Node is a C12.22 Host
    - `NOTIFICATION_HOST` - Node is a C12.22 Notification Host
    - `AUTHENTIcATION_HOST` - Node is a C12.22 Authentication Host
    - `END_DEVICE` - Node is a C12.19 Device
    - `MY_DOMAIN_PATTERN` - the my-domain-pattern parameter is present
    - `RESERVED` - a reserved bit is set

* The **`connection_type`** field is an indication of the type of connection requested and the core capability related to this C12.22 Node in regard to its connection to the C12.22 Network Segment:
    - `BROADCAST_AND_MULTICAST_SUPPORTED` - Node has the capability to accept broadcast and multicast messages
    - `MESSAGE_ACCEPTANCE_WINDOW_SUPPORTED` - Node is capable of implementing time-based C12.22 Message acceptance windows
    - `PLAYBACK_REJECTION_SUPPORTED` - Node is capable of performing playback rejection algorithms
    - `CONNECTIONLESS_MODE_SUPPORTED` - Node is capable of implementing time-based C12.22 Message acceptance windows
    - `ACCEPT_CONNECTIONLESS` - Node is capable of implementing time-based C12.22 Message acceptance windows
    - `CONNECTION_MODE_SUPPORTED` - Node is capable of implementing time-based C12.22 Message acceptance windows
    - `ACCEPT_CONNECTIONS` - Node is capable of implementing time-based C12.22 Message acceptance windows
    - `RESERVED` - a reserved bit is set

* The **`reg_info`** field identifies the following:
    - `DIRECT_MESSAGING_AVAILABLE` - Indicates whether direct messaging is available
    - `MESSAGE_ACCEPTANCE_WINDOW_MODE` - indicates this Node may enable its incoming message acceptance window
    - `PLAYBACK_REJECTION_MODE` - indicates that this Node may enable its playback rejection mechanism
    - `CONNECTIONLESS_MODE` - indicates whether this C12.22 Node shall enable its connectionless-mode communication capability
    - `ACCEPT_CONNECTIONLESS` - the registering node shall accept unsolicited incoming connectionless messages
    - `CONNECTION_MODE` - indicates whether this C12.22 Node shall enable its connection-mode communication capability
    - `ACCEPT_CONNECTIONS` - the registering node shall accept incoming connections
    - `RESERVED` - a reserved bit is set

### Resolve Service Log (c1222_resolve_service.log)

#### Overview

This log provides details of each data field in the Resolve EPSEM services.

#### Fields Captured

| Field                     | Type             | Description                                                              |
| --------------------------|------------------|--------------------------------------------------------------------------|
| ts                        | time             | Timestamp (network time)                                                 |
| uid                       | string           | Unique ID for this connection                                            |
| id                        | conn_id          | Default Zeek connection info (IP addresses, ports)                       |
| proto                     | string           | Transport protocol                                                       |
| req_resp                  | string           | Request/Response                                                         |
| ap_title                  | string           | ApTitle of the requested C12.22 Node                                     |
| local_address             | string           | Local address of the requested ApTitle                                   |

### Trace Service Log (c1222_trace_service.log)

#### Overview

This log provides details of each data field in the Trace EPSEM services.

#### Fields Captured

| Field                     | Type             | Description                                                              |
| --------------------------|------------------|--------------------------------------------------------------------------|
| ts                        | time             | Timestamp (network time)                                                 |
| uid                       | string           | Unique ID for this connection                                            |
| id                        | conn_id          | Default Zeek connection info (IP addresses, ports)                       |
| proto                     | string           | Transport protocol                                                       |
| req_resp                  | string           | Request/Response                                                         |
| ap_titles                 | vector of string | List of Node AP Titles                                                   |

### Service Error Log (c1222_service_error.log)

#### Overview

This log provides details protocol service error.

#### Fields Captured

| Field                     | Type             | Description                                                              |
| --------------------------|------------------|--------------------------------------------------------------------------|
| ts                        | time             | Timestamp (network time)                                                 |
| uid                       | string           | Unique ID for this connection                                            |
| id                        | conn_id          | Default Zeek connection info (IP addresses, ports)                       |
| proto                     | string           | Transport protocol                                                       |
| req_resp                  | string           | Request/Response                                                         |
| service                   | string           | Related Service Request Type generating the Error                        |
| error_code                | string           | Error type generated                                                     |
| rqtl_max_request_size     | int              | Request too large max request size                                       |
| rstl_max_response_size    | int              | Response too large max response size                                     |
| sigerr_resp               | string           | Segmentation Error Response                                              |

## ICSNPP Packages

All ICSNPP Packages:

* [ICSNPP](https://github.com/cisagov/icsnpp)

Full ICS Protocol Parsers:

* [BACnet](https://github.com/cisagov/icsnpp-bacnet)
    * Full Zeek protocol parser for BACnet (Building Control and Automation)
* [BSAP](https://github.com/cisagov/ICSNPP-BSAP)
    * Full Zeek protocol parser for BSAP (Bristol Standard Asynchronous Protocol) over IP
    * Full Zeek protocol parser for BSAP Serial comm converted using serial tap device
* [Ethercat](https://github.com/cisagov/icsnpp-ethercat)
    * Full Zeek protocol parser for Ethercat
* [Ethernet/IP and CIP](https://github.com/cisagov/icsnpp-enip)
    * Full Zeek protocol parser for Ethernet/IP and CIP
* [Genisys](https://github.com/cisagov/icsnpp-genisys)
    * Full Zeek protocol parser for Genisys
* [OPCUA-Binary](https://github.com/cisagov/icsnpp-opcua-binary)
    * Full Zeek protocol parser for OPC UA (OPC Unified Architecture) - Binary
* [S7Comm](https://github.com/cisagov/icsnpp-s7comm)
    * Full Zeek protocol parser for S7comm, S7comm-plus, and COTP
* [Synchrophasor](https://github.com/cisagov/icsnpp-synchrophasor)
    * Full Zeek protocol parser for Synchrophasor Data Transfer for Power Systems (C37.118)
* [Profinet IO CM](https://github.com/cisagov/icsnpp-profinet-io-cm)
    * Full Zeek protocol parser for Profinet I/O Context Manager

Updates to Zeek ICS Protocol Parsers:

* [DNP3](https://github.com/cisagov/icsnpp-dnp3)
    * DNP3 Zeek script extending logging capabilities of Zeek's default DNP3 protocol parser
* [Modbus](https://github.com/cisagov/icsnpp-modbus)
    * Modbus Zeek script extending logging capabilities of Zeek's default Modbus protocol parser

### Other Software
Idaho National Laboratory is a national research facility with a focus on development of software and toolchains to improve the security of criticial infrastructure environments around the world. Please review our other software and scientific offerings at:

[Primary Technology Offerings Page](https://www.inl.gov/inl-initiatives/technology-deployment)

[Supported Open Source Software](https://github.com/idaholab)

[Raw Experiment Open Source Software](https://github.com/IdahoLabResearch)

[Unsupported Open Source Software](https://github.com/IdahoLabCuttingBoard)

### License

Copyright 2025 Battelle Energy Alliance, LLC. Released under the terms of the 3-Clause BSD License (see [`LICENSE`](./LICENSE)).
