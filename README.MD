## How to build

### Dependencies
Required packages might vary from system to system. Below are the packages it was once required to install on a clean DUT CentOS 8 installation 

#### 1. libstdc++
```bash
sudo yum install libstdc++-static
```
#### 2. Onload repository
It is necessary to have a copy of the Onload source code
```bash
git clone git@github.com:Xilinx/onload.git
```

### Building
Execute the following command from the root of the repository:

```bash
export ONLOAD_TREE={path to the checked out onload repository}
make
```
## How to run unit tests

### Dependencies
In addition to the dependencies specified in the build section unit tests would require following dependencies in place:

#### 1. perl-Test-Harness
```bash
$ sudo yum install perl-Test-Harness
```


### Running tests
Execute the following commands from the root of the repository:

```bash
$ export ONLOAD_TREE={path to the checked out onload repository}
$ export ZF_DEVEL=1
$ make clean test
```

*Note: sudo access will be required to run tests*

### Common Problems

1) If you get the problem 'Failed to allocate huge page for emu, are huge pages available?'

```bash
$ sudo sysctl vm.nr_hugepages=4096
```

## Footnotes

```
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (c) 2020-2024 Advanced Micro Devices, Inc.
#
# Internal documentation
```
