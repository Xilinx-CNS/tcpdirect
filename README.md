# TCPDirect

AMD TCPDirect is highly accelerated network middleware. It uses similar techniques to Onload, but delivers lower latency. In order to achieve this, TCPDirect supports a reduced feature set and uses a proprietary API.

AMD TCPDirect should be used with corresponding versions of Onload®️ at https://github.com/Xilinx-CNS/onload.


## Features

* User-space: TCPDirect can be used by unprivileged user-space applications.
* Kernel bypass: Data path operations do not require system calls.
* Low CPU overhead: Data path operations consume very few CPU cycles.
* Low latency: Suitable for low latency applications.
* High packet rates: Supports millions of packets per second per core.
* Zero-copy: Particularly efficient for filtering and forwarding applications.
* Flexibility: Supports many use cases.


## Installation and Quick Start Guide

Recent releases of TCPDirect are distributed as source code. Instructions for building, packaging and installing may be found in [DEVELOPING.md](DEVELOPING.md)


## Support

The publicly-hosted repository is a community-supported project. When raising
issues on this repository it is expected that users will be running
from the head of the git tree to pick up recent changes.

Supported releases of TCPDirect are available from
<https://www.xilinx.com/support/download/nic-software-and-drivers.html#tcpdirect>.
Please raise issues on _supported releases_ of TCPDirect with
<support-nic@amd.com>.


## Contributions

Please see [CONTRIBUTING.md](CONTRIBUTING.md)


## Footnotes

```yaml
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: Copyright (C) 2020-2024 Advanced Micro Devices, Inc.
```
