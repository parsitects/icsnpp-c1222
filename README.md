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
* `.log`
* `.log`
* `.log`
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
$ zeek -C -r c1222_tcp.pcap local "SYNCHROPHASOR::c1222_ports_tcp={ 40712/tcp }"
```

#### Fields Captured

| Field                 | Type           | Description                                               |
| ----------------------|----------------|-----------------------------------------------------------| 
| ts                    | time           | Timestamp (network time)                                  |
| uid                   | string         | Unique ID for this connection                             |
| id                    | conn_id        | Default Zeek connection info (IP addresses, ports)        |
| proto                 | string         | Transport protocol                                        |
| elements              | set<string>    | List of the ASCE Elements utilized in the packet          |
| is_encrypted_epsem    | bool           | Flag denoting if the EPSEM data is encrypted              |
| services              | set<string>    | List of epsem services in the packet                      |
| aso_context           | string         | Application context universal identifier                  |
| called_ap_title       | string         | Unique identifier of message target                       |
| calling_ap_title      | string         | Unique identifier of message initiator                    |
| calling_ae_qualifier  | set<string>    | Qualifies data being sent                                 |
| mechanism name        | string         | Unique security mechanism identifier                      |
| calling_auth_value    | string         | Authenticatin mechanism used                              |
| 
        calling_ae_qualifier: vector of string &optional &log;
        mechanism_name: string &optional &log;
        calling_auth_value: string &optional &log; #will list the mechanism name. Details in another log.
        called_ap_invocation_id: string &optional &log;
        calling_ap_invocation_id: string &optional &log;

* The **`calling_ae_qualifer`** field is comprised of four non-exclusive qualifiers:
    - `TEST` - test message
    - `URGENT` - high priority message
    - `NOTIFICATION` - write services issued as a notification
    - `RESERVED` - a reserved bit is set
* The **`calling_auth_value`** field contains a summary of the authentication mechanism used. Details of the calling 
authentication value can be found in `c1222_authentication_value.log`.

### Synchrophasor Command Frame Log (synchrophasor_cmd.log)

#### Overview

This log summarizes synchrophasor Command frames.

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
| command           | string         | String represetnation of the command                      |
| extframe          | vector<count>  | Extended frame data (user-defined)                        |

### Synchrophasor Header Frame Log (synchrophasor_hdr.log)

#### Overview

This log summarizes synchrophasor Header frames.

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

### Synchrophasor Configuration Frame Log (synchrophasor_cfg.log)

#### Overview

This log summarizes synchrophasor Configuration (CFG-1, CFG-2, and CFG-3) frames.

#### Fields Captured

| Field              | Type           | Description                                               |
| -------------------|----------------|-----------------------------------------------------------|
| ts                 | time           | Timestamp (network time)                                  |
| uid                | string         | Unique ID for this connection                             |
| id                 | conn_id        | Default Zeek connection info (IP addresses, ports)        |
| proto              | string         | Transport protocol                                        |
| frame_type         | string         | Frame type from synchrophasor frame synchronization word  |
| frame_size         | count          | Frame size (in bytes)                                     |
| header_time_stamp  | time           | Timestamp from frame header                               |
| cont_idx           | count          | Continuation index for fragmented frames                  |
| pmu_count_expected | count          | The number of PMUs expected in the configuration frame    |
| pmu_count_actual   | count          | The number of PMUs included in the configuration frame    |
| cfg_frame_id       | string         | Unique string to correlate with synchrophasor_cfg_detail  |

### Synchrophasor Configuration PMU Details (synchrophasor_cfg_detail.log)

#### Overview

This log lists the per-PMU details from synchrophasor Configuration (CFG-1, CFG-2, and CFG-3) frames. As this can be very verbose, this log file is **disabled** by default. Users can enable it by appending `SYNCHROPHASOR::log_cfg_detail=T` to the `zeek` command on the command line or by adding `redef SYNCHROPHASOR::log_cfg_detail = T;` to the `local.zeek` file.

#### Fields Captured

Most of the fields listed here are optional. Many may be unused during communication depending on device configuration. See IEEE Std C37.118.2-2011 for more details.


| Field                                          | Type           | Description                                                                  |
| -----------------------------------------------|----------------|------------------------------------------------------------------------------|
| ts                                             | time           | Timestamp (network time)                                                     |
| uid                                            | string         | Unique ID for this connection                                                |
| id                                             | conn_id        | Default Zeek connection info (IP addresses, ports)                           |
| proto                                          | string         | Transport protocol                                                           |
| frame_type                                     | string         | Frame type from synchrophasor frame synchronization word                     |
| header_time_stamp                              | time           | Timestamp from frame header                                                  |
| cfg_frame_id                                   | string         | Unique string to correlate with synchrophasor_cfg                            |
| pmu_idx                                        | count          | 0-based index of PMU configuration within the CFG frame                      |
| svc_class                                      | string         | Service class as defined in IEEE Std C37.118.1                               |
| station_name                                   | string         | Station name                                                                 |
| data_source_id                                 | count          | Data source id                                                               |
| global_pmuid                                   | string         | Global PMU ID                                                                |
| phasor_shape                                   | bool           | F = phasor real and imaginary (rectangular), T = magnitude and angle (polar) |
| phasor_format                                  | bool           | F = phasors 16-bit integer, T = floating point                               |
| analog_format                                  | bool           | F = analogs 16-bit integer, T = floating point                               |
| freq_format                                    | bool           | 0 = FREQ/DFREQ 16-bit integer, 1 = floating point                            |
| phnmr                                          | count          | Number of phasors                                                            |
| annmr                                          | count          | Number of analog values                                                      |
| dgnmr                                          | count          | Number of digital status words                                               |
| phnam                                          | vector<string> | Phasor channel names                                                         |
| annam                                          | vector<string> | Analog channel names                                                         |
| dgnam                                          | vector<string> | Digital channel names                                                        |
| phasor_conv_phunit                             | vector<count>  | Phasor conversion factor format unit                                         |
| phasor_conv_phvalue                            | vector<count>  | Phasor conversion factor format value                                        |
| phasor_conv_upsampled_interpolation            | vector<bool>   | Up sampled with interpolation                                                |
| phasor_conv_upsampled_extrapolation            | vector<bool>   | Upsampled with extrapolation                                                 |
| phasor_conv_downsampled_reselection            | vector<bool>   | Down sampled by reselection (selecting every Nth sample)                     |
| phasor_conv_downsampled_fir_filter             | vector<bool>   | Down sampled with FIR filter                                                 |
| phasor_conv_downsampled_no_fir_filter          | vector<bool>   | Down sampled with non-FIR filter                                             |
| phasor_conv_filtered_without_changing_sampling | vector<bool>   | Filtered without changing sampling                                           |
| phasor_conv_calibration_mag_adj                | vector<bool>   | Phasor magnitude adjusted for calibration                                    |
| phasor_conv_calibration_phas_adj               | vector<bool>   | Phasor phase adjusted for calibration                                        |
| phasor_conv_rotation_phase_adj                 | vector<bool>   | Phasor phase adjusted for rotation ( ±30o, ±120o, etc.)                      |
| phasor_conv_pseudo_phasor_val                  | vector<bool>   | Pseudo-phasor value (combined from other phasors)                            |
| phasor_conv_mod_appl                           | vector<bool>   | Modification applied, type not here defined                                  |
| phasor_conv_phasor_component                   | vector<count>  | Phasor component (see std. spec)                                             |
| phasor_conv_phasor_type                        | vector<bool>   | F = voltage, T = current                                                     |
| phasor_conv_user_def                           | vector<count>  | User-defined                                                                 |
| phasor_conv_scale_factor                       | vector<double> | Scale factor Y                                                               |
| phasor_conv_angle_adj                          | vector<double> | Phasor angle adjustment θ                                                    |
| analog_conv_analog_flags                       | vector<count>  | Analog flags                                                                 |
| analog_conv_user_defined_scaling               | vector<int>    | User-defined scaling                                                         |
| analog_conv_mag_scale                          | vector<double> | Magnitude scale factor                                                       |
| analog_conv_offset                             | vector<double> | Angle offset                                                                 |
| digital_conv_normal_status_mask                | vector<count>  | Digital input normal status mask                                             |
| digital_conv_valid_inputs_mask                 | vector<count>  | Digital input valid inputs status mask                                       |
| pmu_lat                                        | double         | PMU latitude in degrees                                                      |
| pmu_lon                                        | double         | PMU longitude in degrees                                                     |
| pmu_elev                                       | double         | PMU elevation in meters                                                      |
| window                                         | int            | Phasor measurement window length                                             |
| group_delay                                    | int            | Phasor measurement group delay                                               |
| fnom                                           | count          | Nominal line frequency code                                                  |
| cfgcnt                                         | count          | Configuration change count                                                   |

### Synchrophasor Data Frame Log (synchrophasor_data.log)

#### Overview

This log summarizes synchrophasor Data frames. As this can be very verbose, this log file is **disabled** by default. You can enable it by appending `SYNCHROPHASOR::log_data_frame=T` to your `zeek` command on the command line or by adding `redef SYNCHROPHASOR::log_data_frame = T;` to your `local.zeek` file.

#### Fields Captured

| Field              | Type           | Description                                               |
| -------------------|----------------|-----------------------------------------------------------|
| ts                 | time           | Timestamp (network time)                                  |
| uid                | string         | Unique ID for this connection                             |
| id                 | conn_id        | Default Zeek connection info (IP addresses, ports)        |
| proto              | string         | Transport protocol                                        |
| frame_type         | string         | Frame type from synchrophasor frame synchronization word  |
| frame_size         | count          | Frame size (in bytes)                                     |
| header_time_stamp  | time           | Timestamp from frame header                               |
| pmu_count_expected | count          | The number of PMUs expected in the data frame             |
| pmu_count_actual   | count          | The number of PMUs included in the data frame             |
| data_frame_id      | string         | Unique string to correlate with synchrophasor_data_detail |

### Synchrophasor Data PMU Details Log (synchrophasor_data_detail.log)

#### Overview

This log lists the per-PMU details from synchrophasor Data frames. As this can be very verbose, this log file is **disabled** by default. You can enable it by appending `SYNCHROPHASOR::log_data_detail=T` to your `zeek` command on the command line or by adding `redef SYNCHROPHASOR::log_data_detail = T;` to your `local.zeek` file. Note that `log_data_frame` described above must also be set to `T` for `log_data_detail` to take effect.

Most of the fields listed here are optional. Many may be unused during communication depending on device configuration. See IEEE Std C37.118.2-2011 for more details.

#### Fields Captured

| Field                           | Type           | Description                                                  |
| --------------------------------|----------------|--------------------------------------------------------------|
| ts                              | time           | Timestamp (network time)                                     |
| uid                             | string         | Unique ID for this connection                                |
| id                              | conn_id        | Default Zeek connection info (IP addresses, ports)           |
| proto                           | string         | Transport protocol                                           |
| frame_type                      | string         | Frame type from synchrophasor frame synchronization word     |
| header_time_stamp               | time           | Timestamp from frame header                                  |
| data_frame_id                   | string         | Unique string to correlate with synchrophasor_data_detail    |
| pmu_idx                         | count          | 0-based index of PMU data within the data frame              |
| trigger_reason                  | count          | Trigger reason                                               |
| unlocked_time                   | count          | Unlocked time                                                |
| pmu_time_quality                | count          | PMU time quality                                             |
| data_modified                   | bool           | T = data made by post-processing, F = otherwise              |
| config_change                   | bool           | T = confiuration change advised, F = change effected         |
| pmu_trigger_pickup              | bool           | T = PMU trigger detected, F = no trigger                     |
| data_sorting_type               | bool           | F = sort by time stamp, T = sort by arrival                  |
| pmu_sync_error                  | bool           | T = time sync error, F = PMU in sync with time source        |
| data_error_indicator            | count          | Data error indicator                                         |
| est_rectangular_real            | vector<double> | Phasor estimate: rectangular real value                      |
| est_rectangular_imaginary       | vector<double> | Phasor estimate: rectangular imaginary value                 |
| est_polar_magnitude             | vector<double> | Phasor estimate: polar magnitude value                       |
| est_polar_angle                 | vector<double> | Phasor estimate: polar angle radians                         |
| freq_dev_mhz                    | double         | Frequency deviation from nominal, in mHz                     |
| rocof                           | double         | ROCOF, in hertz per second times 100                         |
| analog_data                     | vector<double> | User-defined analog data value                               |
| digital                         | vector<count>  | User-defined digital status word                             |

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

Copyright 2023 Battelle Energy Alliance, LLC. Released under the terms of the 3-Clause BSD License (see [`LICENSE`](./LICENSE)).
