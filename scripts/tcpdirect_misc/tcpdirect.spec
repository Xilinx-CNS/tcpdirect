# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (c) 2016-2023 Advanced Micro Devices, Inc.
######################################################################

%define _unpackaged_files_terminate_build 0
pkgversion-DEFINITION

Name:           tcpdirect
Version:        %{pkgversion}
Release:        1
Summary:        TCPDirect

License:        MIT AND BSD-3-Clause AND LGPL-3.0
URL:            https://github.com/Xilinx-CNS/tcpdirect
Source0:        tcpdirect-%{pkgversion}.tgz

Vendor:         Advanced Micro Devices, Inc.

ExclusiveArch:  x86_64
Requires:       openonload

%description
tcpdirect is a high performance user-level network stack. 

This package comprises the user space components of tcpdirect.



%prep
[ "$RPM_BUILD_ROOT" != / ] && rm -rf "$RPM_BUILD_ROOT"
mkdir -p $RPM_BUILD_ROOT




%build
tar -xzvf %{_sourcedir}/tcpdirect-%{pkgversion}.tgz -C $RPM_BUILD_ROOT
ls -la $RPM_BUILD_ROOT
ls -la $RPM_BUILD_ROOT/tcpdirect-%{pkgversion}/scripts
# $RPM_BUILD_ROOT/tcpdirect-%{pkgversion}/scripts/zf_install


mkdir -p $RPM_BUILD_ROOT/%{_bindir}/
mv $RPM_BUILD_ROOT/tcpdirect-%{pkgversion}/scripts/zf_debug $RPM_BUILD_ROOT/%{_bindir}/
mv $RPM_BUILD_ROOT/tcpdirect-%{pkgversion}/release/bin/* $RPM_BUILD_ROOT/%{_bindir}/

mkdir -p $RPM_BUILD_ROOT/%{_libdir}/zf
mkdir -p $RPM_BUILD_ROOT/%{_libdir}/zf/debug
mv $RPM_BUILD_ROOT/tcpdirect-%{pkgversion}/release/lib/* $RPM_BUILD_ROOT/%{_libdir}/
mv $RPM_BUILD_ROOT/tcpdirect-%{pkgversion}/debug/lib/* $RPM_BUILD_ROOT/%{_libdir}/zf/debug/

mkdir -p $RPM_BUILD_ROOT/%{_includedir}/zf
mv $RPM_BUILD_ROOT/tcpdirect-%{pkgversion}/src/include/zf/* $RPM_BUILD_ROOT/%{_includedir}/zf

mkdir -p $RPM_BUILD_ROOT/%{_datadir}/doc/tcpdirect/examples
mv $RPM_BUILD_ROOT/tcpdirect-%{pkgversion}/LICENSE $RPM_BUILD_ROOT/%{_datadir}/doc/tcpdirect
mv $RPM_BUILD_ROOT/tcpdirect-%{pkgversion}/src/tests/* $RPM_BUILD_ROOT/%{_datadir}/doc/tcpdirect/examples/


%files
%defattr(-,root,root)
%{_bindir}/zf_debug
%{_bindir}/zf_stackdump
# Ownership for debug binaries
%{_libdir}/zf/*
# Ownership for release binaries
%{_libdir}/libonload_zf* 
%{_includedir}/zf/*
%{_datadir}/doc/tcpdirect/*
# %license add-license-file-here
# %doc add-docs-here



%changelog
* Tue Feb  1 2022 Thomas Crawley
- 
