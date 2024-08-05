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

### Packaging
Use the [`zf_make_official_srpm`](./scripts/zf_make_official_srpm) script to create an SRPM package:

```bash
scripts/zf_make_official_srpm --version ${version}
```

The `${version}` variable can be git hexsha such as `d42f94d5` or a semver string such as `9.0.0`.

Execute the following command to create an RPM package from SRPM:

```bash
rpmbuild --rebuild ~/rpmbuild/SRPMS/tcpdirect-${version}-1.src.rpm
```

Here, the `${version}` variable is the same as for `zf_make_official_srpm`.
The above command will build the tcpdirect package using the onload libraries
installed as part of the `onload` rpm package, and the headers from the
`onload-devel` package.

If you wish to build the tcpdirect package either from a specific onload tarball
or without installing the system packages, you can add the following to the
invocation of `rpmbuild` above:

```bash
--define "onload_tarball ${onload}"
```

Where the `${onload}` variable points to an Onload tarball.

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
