# Table of contents

[Introduction](#Introduction) 

[Build](#Build)

[Installation](#Installation)

[Usage](#Usage)

[Configuration](#Configuration)

* [BGP configuration](#BGP-configuration)

* [Sampling configuration](#Sampling-configuration)

* [Telemetry configuration](#Telemetry-configuration)

* [Management configuration](#Management-configuration)

[Verification and troubleshooting](#Verification-and-troubleshooting)

* [Telemetry and sampling](#Telemetry-and-sampling)

* [BGP](#BGP)

[Supported OS](#Supported-OS)

[Limitations](#Limitations)


# Introduction

SR-TE bandwidth sampler connects to routers using GNMI, fetches SR policy counters, calculates average bandwidth and creates a BGP-LS NLRI per RFC9857, with SR bandwidth constraint TLV.

This can be used together with Traffic Dictator (or another PCE with RFC9857 support) to implement an auto-bandwidth solution with Segment Routing.

Current version 0.1 is experimental and is suitable for development and lab usage, not yet recommended for production networks.

# Build

This step is not necessary, you can just pull a pre-built docker container from docker hub (see next step).

Pull the repository and run the build script (as root):
```
./sampler_builder.py
```
This will create a docker image on your machine and archive srte-sampler-0.1.tar.gz

# Installation

Pull the existing container from docker hub:

```
sudo docker pull vegvisirsystems/srte-sampler:latest
```

Or just run:

```
sudo docker run --name SAMPLER --hostname SAMPLER --privileged -d vegvisirsystems/srte-sampler:0.1
```

With host networking (best option if you have a dedicated VM for sampler):

```
sudo docker run --name SAMPLER --hostname SAMPLER --privileged --network=host -d vegvisirsystems/srte-sampler:0.1
```

# Usage

Connect to container:

```
sudo docker exec -it SAMPLER cli
```

# Configuration

SRTE sampler provides an industry-standard CLI. Some parts of the configuration (BGP and management) are similar to Traffic Dictator.

## BGP configuration

Sampler uses BGP-LS to advertise SR-TE policies to the PCE using RFC9857 format.

Config model:

```
router bgp <asn>
   router-id <ipv4>
   !
   neighbor <ipv4|ipv6>
      description <name>
      remote-as <asn>
      timers <ka> <hold>
      ebgp-multihop <1-255>
      shutdown
```

Config example:

```
router bgp 65001
   !
   neighbor 192.168.101.102
      remote-as 65002
      ebgp-multihop 2
```

There is no need to configure address families because the only supported AF is BGP-LS.

## Sampling configuration

Config model:

```
sampling options
   sampling interval <10-300 s>
   sampling database <>
   adjust interval <60-604800 s>
   adjust threshold <0-100>
```

Sampling interval: how frequently SR-TE counter samples are collected
Sampling database: file path for the sampling database file (can be on NFS). If not configured, SRTE sampler will create a local DB file in the docker container (/usr/local/sampler/srte_sampling.db)
Adjust interval: how frequently SR policy bandwidth rates are adjusted (need to be at least 6 times the sampling interval)
Adjust threshold (in percentage): how much the policy bandwidth needs to change to trigger adjustment


## Telemetry configuration

Config model:

```
telemetry profiles
   !
   profile <name>
      os [iosxr|junos|eos]
	    port <1-65535>
	    auth [password|certificate]
	    username <username>
	    password <password>
!
telemetry clients
   !
   group <name>
      client <ipv4|ipv6>
	    profile <name>
```

This controls GNMI clients. Currently only password authentication is supported. 

Config example:

```
telemetry profiles
   !
   profile EOS_PROFILE
      os eos
      port 6030
      auth password
      username admin
      password admin
   !
   profile IOSXR_PROFILE
      os iosxr
      port 57400
      auth password
      username clab
      password clab@123
   !
   profile JUNOS_PROFILE
      os junos
      port 32767
      auth password
      username admin
      password admin@123
!
telemetry clients
   !
   group EOS_CLIENTS
      profile EOS_PROFILE
      client 192.168.102.107
      client 192.168.102.108
   !
   group IOSXR_CLIENTS
      profile IOSXR_PROFILE
      client 192.168.102.102
   !
   group JUNOS_CLIENTS
      profile JUNOS_PROFILE
      client 192.168.102.101
```

## Management configuration

This controls API, syslog and local user configuration. Config model:

```
management api http-commands
   !
   protocol http
      port <1-65535>
      shutdown
   !
   protocol https
      port <1-65535>
      certificate <> key <>
      shutdown
!
management syslog
   ! 
   host <ipv4|ipv6>
      protocol [udp|tcp]
      port <1-65535>
!
management users
   ! 
   user <name>
      password [cleartext|encrypted] <>
```

Management configuration is exactly the same as for Traffic Dictator, see TD configuration guide: https://vegvisir.ie/http-api-configuration/


# Verification and troubleshooting

## Telemetry and sampling

Check telemetry clients and sampled policies:

```
lmk-vm103-dev-bw-sampler#show sampling summary 
Sampling summary information

    Sampling interval                        10
    Adjust interval:                         60
    Actual adjust interval:                  60
    Adjust threshold:                        10
    Last adjusted:                           0:00:37
    Sampling DB path:                        /home/dima/srte-bw-sampler/srte_sampling.db

  Sampler              Valid config    Running         OS            Auth       Last read time
  192.168.102.107              True       True        eos        password              0:00:08
  192.168.102.108              True       True        eos        password              0:00:08
  192.168.102.102              True       True      iosxr        password              0:00:08
  192.168.102.101              True       True      junos        password              0:00:07
```

```
lmk-vm103-dev-bw-sampler#show sampling policies
Sampling policies information
Number of policies: 24, active 24, stale 0 
Status codes: ~ stale

    Policy                                                   Rate                   Last updated
    [1.1.1.1][2.2.2.2][101]                            5.049 Gbps                        0:00:03
    [1.1.1.1][2.2.2.2][202]                           40.388 Gbps                        0:00:03
    [1.1.1.1][7.7.7.7][101]                            4.984 Gbps                        0:00:03
    [1.1.1.1][7.7.7.7][202]                           39.116 Gbps                        0:00:03
    [1.1.1.1][8.8.8.8][101]                            4.918 Gbps                        0:00:03
    [1.1.1.1][8.8.8.8][202]                           40.321 Gbps                        0:00:03
    [2.2.2.2][1.1.1.1][101]                            4.954 Gbps                        0:00:03
    [2.2.2.2][1.1.1.1][202]                           40.963 Gbps                        0:00:03
    [2.2.2.2][7.7.7.7][101]                            4.873 Gbps                        0:00:03
    [2.2.2.2][7.7.7.7][202]                           40.467 Gbps                        0:00:03
    [2.2.2.2][8.8.8.8][101]                            5.011 Gbps                        0:00:03
    [2.2.2.2][8.8.8.8][202]                           39.856 Gbps                        0:00:03
    [7.7.7.7][1.1.1.1][101]                            4.919 Gbps                        0:00:03
    [7.7.7.7][1.1.1.1][202]                           39.333 Gbps                        0:00:03
    [7.7.7.7][2.2.2.2][101]                            4.975 Gbps                        0:00:03
    [7.7.7.7][2.2.2.2][202]                           40.211 Gbps                        0:00:03
    [7.7.7.7][8.8.8.8][101]                            4.973 Gbps                        0:00:03
    [7.7.7.7][8.8.8.8][202]                           39.879 Gbps                        0:00:03
    [8.8.8.8][1.1.1.1][101]                            4.986 Gbps                        0:00:03
    [8.8.8.8][1.1.1.1][202]                           40.270 Gbps                        0:00:03
    [8.8.8.8][2.2.2.2][101]                            4.921 Gbps                        0:00:03
    [8.8.8.8][2.2.2.2][202]                           39.236 Gbps                        0:00:03
    [8.8.8.8][7.7.7.7][101]                            5.048 Gbps                        0:00:03
    [8.8.8.8][7.7.7.7][202]                           39.378 Gbps                        0:00:03
```

```
lmk-vm103-dev-bw-sampler#show sampling policies [1.1.1.1][2.2.2.2][101] detail 
Detailed sampling policies information
Number of policies: 1, active 1, stale 0 

Sampled policy entry for [1.1.1.1][2.2.2.2][101]
  Router-id: 1.1.1.1
  Endpoint: 2.2.2.2
  Color: 101
  Rate   5.049 Gbps, calculated from 6 samples within 50.4 seconds
  Last updated: 0:00:18 ago
```

## BGP

Sampled policies are converted to BGP-LS NLRI per RFC9857. 

Check BGP neighbors:

```
lmk-vm103-dev-bw-sampler#sh bgp summary 
BGP summary information
Router identifier 100.2.2.2, local AS number 65001
  Neighbor             V    AS          MsgRcvd  MsgSent      InQ     OutQ      Up/Down    State          Received NLRI    Active AF
  192.168.102.102      4    65002            89       38        0        0      0:11:44    Established               96    LS
```

Check BGP-LS routes:

```
lmk-vm103-dev-bw-sampler#sh bgp link-state | grep SP

Prefix codes: E link, V node, T IP reacheable route, S SRv6 SID, SP SRTE Policy, u/U unknown,
          L1/L2 ISIS level-1/level-2, O OSPF, D direct, S static/peer-node,
          i if-address, n nbr-address, o OSPF Route-type, p IP-prefix,
       [SP][SR][I0][N[c65001][b0][q1.1.1.1][1.1.1.1]][C[po2][f0][e2.2.2.2][c101][as65001][oa1.1.1.1][di100]]
       [SP][SR][I0][N[c65001][b0][q1.1.1.1][1.1.1.1]][C[po2][f0][e2.2.2.2][c202][as65001][oa1.1.1.1][di100]]
       [SP][SR][I0][N[c65001][b0][q1.1.1.1][1.1.1.1]][C[po2][f0][e7.7.7.7][c101][as65001][oa1.1.1.1][di100]]
       [SP][SR][I0][N[c65001][b0][q1.1.1.1][1.1.1.1]][C[po2][f0][e7.7.7.7][c202][as65001][oa1.1.1.1][di100]]
       [SP][SR][I0][N[c65001][b0][q1.1.1.1][1.1.1.1]][C[po2][f0][e8.8.8.8][c101][as65001][oa1.1.1.1][di100]]
       [SP][SR][I0][N[c65001][b0][q1.1.1.1][1.1.1.1]][C[po2][f0][e8.8.8.8][c202][as65001][oa1.1.1.1][di100]]
       [SP][SR][I0][N[c65001][b0][q2.2.2.2][2.2.2.2]][C[po2][f0][e1.1.1.1][c101][as65001][oa2.2.2.2][di100]]
       [SP][SR][I0][N[c65001][b0][q2.2.2.2][2.2.2.2]][C[po2][f0][e1.1.1.1][c202][as65001][oa2.2.2.2][di100]]
       [SP][SR][I0][N[c65001][b0][q2.2.2.2][2.2.2.2]][C[po2][f0][e7.7.7.7][c101][as65001][oa2.2.2.2][di100]]
       [SP][SR][I0][N[c65001][b0][q2.2.2.2][2.2.2.2]][C[po2][f0][e7.7.7.7][c202][as65001][oa2.2.2.2][di100]]
       [SP][SR][I0][N[c65001][b0][q2.2.2.2][2.2.2.2]][C[po2][f0][e8.8.8.8][c101][as65001][oa2.2.2.2][di100]]
       [SP][SR][I0][N[c65001][b0][q2.2.2.2][2.2.2.2]][C[po2][f0][e8.8.8.8][c202][as65001][oa2.2.2.2][di100]]
       [SP][SR][I0][N[c65001][b0][q7.7.7.7][7.7.7.7]][C[po2][f0][e1.1.1.1][c101][as65001][oa7.7.7.7][di100]]
       [SP][SR][I0][N[c65001][b0][q7.7.7.7][7.7.7.7]][C[po2][f0][e1.1.1.1][c202][as65001][oa7.7.7.7][di100]]
       [SP][SR][I0][N[c65001][b0][q7.7.7.7][7.7.7.7]][C[po2][f0][e2.2.2.2][c101][as65001][oa7.7.7.7][di100]]
       [SP][SR][I0][N[c65001][b0][q7.7.7.7][7.7.7.7]][C[po2][f0][e2.2.2.2][c202][as65001][oa7.7.7.7][di100]]
       [SP][SR][I0][N[c65001][b0][q7.7.7.7][7.7.7.7]][C[po2][f0][e8.8.8.8][c101][as65001][oa7.7.7.7][di100]]
       [SP][SR][I0][N[c65001][b0][q7.7.7.7][7.7.7.7]][C[po2][f0][e8.8.8.8][c202][as65001][oa7.7.7.7][di100]]
       [SP][SR][I0][N[c65001][b0][q8.8.8.8][8.8.8.8]][C[po2][f0][e1.1.1.1][c101][as65001][oa8.8.8.8][di100]]
       [SP][SR][I0][N[c65001][b0][q8.8.8.8][8.8.8.8]][C[po2][f0][e1.1.1.1][c202][as65001][oa8.8.8.8][di100]]
       [SP][SR][I0][N[c65001][b0][q8.8.8.8][8.8.8.8]][C[po2][f0][e2.2.2.2][c101][as65001][oa8.8.8.8][di100]]
       [SP][SR][I0][N[c65001][b0][q8.8.8.8][8.8.8.8]][C[po2][f0][e2.2.2.2][c202][as65001][oa8.8.8.8][di100]]
       [SP][SR][I0][N[c65001][b0][q8.8.8.8][8.8.8.8]][C[po2][f0][e7.7.7.7][c101][as65001][oa8.8.8.8][di100]]
       [SP][SR][I0][N[c65001][b0][q8.8.8.8][8.8.8.8]][C[po2][f0][e7.7.7.7][c202][as65001][oa8.8.8.8][di100]]
```

Check one specific BGP-LS NLRI:

```
lmk-vm103-dev-bw-sampler#sh bgp link-state [SP][SR][I0][N[c65001][b0][q1.1.1.1][1.1.1.1]][C[po2][f0][e2.2.2.2][c101][as65001][oa1.1.1.1][di100]] detail 
BGP-LS routing table information
Router identifier 100.2.2.2, local AS number 65001
Prefix codes: E link, V node, T IP reacheable route, S SRv6 SID, SP SRTE Policy, u/U unknown,
          I Identifier, N local node, R remote node, L link, P prefix, S SID,
          L1/L2 ISIS level-1/level-2, O OSPF, D direct, S static/peer-node,
          a area-ID, l link-ID, t topology-ID, s ISO-ID,
          c confed-ID/ASN, b bgp-identifier, r router-ID, s SID,
          i if-address, n nbr-address, o OSPF Route-type, p IP-prefix,
          d designated router address

BGP routing table entry for [SP][SR][I0][N[c65001][b0][q1.1.1.1][1.1.1.1]][C[po2][f0][e2.2.2.2][c101][as65001][oa1.1.1.1][di100]]
NLRI Type: sr_policy
Protocol: None
Identifier: 0
Local Node Descriptor:
      AS Number: 65001
      BGP Identifier: 0.0.0.0
      BGP Router Identifier: 1.1.1.1
      TE Router Identifier: 1.1.1.1
SRTE Policy CP Descriptor:
      Protocol origin: SR Policy
      Flags: 0
      Endpoint: 2.2.2.2
      Color: 101
      AS Number: 65001
      Originator Address: 1.1.1.1
      Discriminator: 100
Paths: 1 available, best #1
  Last modified: February 25, 2026 20:58:47
  Local
    - from - (0.0.0.0)
      Origin igp, metric 0, localpref -, weight 0, valid, -, best
      Link-state: SRTE Bandwidth rate bps 5048885163
```

Traffic Dictator (https://vegvisir.ie/products/) can receive these NLRI and adjust bandwidth reservations based on measured bandwidth rate. For instance (output from TD):

```
lmk-vm102-dev-td1#sh traffic-eng mesh-template policies mesh_h1.1.1.1_e2.2.2.2_c101
Traffic-eng policy information
Status codes: * active, > installed, r - RSVP-TE, e - EPE only, s - admin down, m - multi-topology
Endpoint codes: * active override
        Policy name                             Headend             Endpoint            Color/Service loopback   Protocol             Reserved bandwidth        Priority   Status/Reason
    *>  mesh_h1.1.1.1_e2.2.2.2_c101             1.1.1.1             2.2.2.2             101                      SR-TE/indirect         5.049 Gbps              5/5        Active/Installed
```

# Supported OS

Currently SRTE sampler supports:

* IOS-XR
* EOS
* JUNOS

# Limitations

This is a prototype, there are a lot of limitations.

* Dynamic config change restarts all GNMI clients
* Only password authentication is supported
* Only BGP passive mode is supported
