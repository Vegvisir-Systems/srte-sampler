# Table of contents

[Introduction](#Introduction) 

[Build](#Build)

[Installation](#Installation)

[Usage](#Usage)

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

Preferred
```
./sampler_builder.py
```

# Usage
