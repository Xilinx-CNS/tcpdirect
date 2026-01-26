/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Copyright 2025 Advanced Micro Devices, Inc. */

@Library('onload_jenkins_pipeline_lib')
import com.solarflarecom.onload.utils.UtilityManager


import groovy.transform.Field

class ZfPipeline implements Serializable {

  def script
  def utils

  ZfPipeline(script, utils) {
    this.script = script
    this.utils = utils
  }

  Properties get_version_info(String tcpdirect_dir) {
    String versionsFileContents = script.readFile("${tcpdirect_dir}/versions.env")
    Properties props = new Properties()
    props.load(new StringReader(versionsFileContents))
    if( ! props.containsKey("TCPDIRECT_VERSION") ) {
      error("Failed to extract TCPDirect version")
    }
    props.TCPDIRECT_VERSION = "${props.TCPDIRECT_VERSION}.${script.env.BUILD_NUMBER}"
    return props
  }

  void extractNotes(String scripts_dir, String tarball) {
    script.sh "${scripts_dir}/tcpdirect_misc/tcpdirect-extract-notes ${tarball}"
  }

  void zip_and_archive_files(String zipfile, String ... files_to_zip) {
    def cmd = [ 'zip', '-j', "'${zipfile}'" ]
    cmd += files_to_zip.collect { f -> "${f}" }
    script.sh(cmd.join(' '))
    script.archiveArtifacts(zipfile)
  }

  Map doPipeline(String tcpdirect_stash,
                 String onload_stash,
                 String onload_tarball_stash,
                 String onload_tarball,
                 version_info)
  {
    def package_locations = [:]

    script.stage('Parallel builds') {
      utils.parallel(
        'build ndebug': {
          script.node('unit-test-master') {
            script.deleteDir()
            script.unstash(tcpdirect_stash)
            script.unstash(onload_stash)
            script.sh 'ls -lad $PWD'
            def CC = script.sh(script: 'ls -1d /opt/rh/devtoolset-{11,10,9,8}/root/usr/bin/cc $(which cc) 2>/dev/null | head -1',
                        returnStdout: true)
            script.sh """#!/bin/bash
              export CC=${CC}
              export ONLOAD_TREE=\$PWD/onload
              export NDEBUG=1
              make -C tcpdirect
            """
            
            // FIXME stash libraries to publish later
            // including a package with debug
          }
        },
        'build libzf_sockets': {
          script.node('unit-test-master') {
            script.deleteDir()
            script.unstash(tcpdirect_stash)
            script.unstash(onload_stash)
            script.sh 'ls -lad $PWD'
            def CC = script.sh(script: 'ls -1d /opt/rh/devtoolset-{11,10,9,8}/root/usr/bin/cc $(which cc) 2>/dev/null | head -1',
                        returnStdout: true)
            script.sh """#!/bin/bash
              export CC=${CC}
              export ONLOAD_TREE=\$PWD/onload
              export NDEBUG=1
              export ZF_DEVEL=1
              make -C tcpdirect shim
            """
          }
        },
        'run tests': {
          script.node('unit-test-master') {
            script.deleteDir()
            script.unstash(tcpdirect_stash)
            script.unstash(onload_stash)
            script.sh 'ls -lad $PWD'
            def CC = script.sh(script: 'ls -1d /opt/rh/devtoolset-{11,10,9,8}/root/usr/bin/cc $(which cc) 2>/dev/null | head -1',
                        returnStdout: true)
            script.dir('test-results') { // ensure folder exists
            }
            // Makefiles do not support gcov build yet
            def rc = script.sh(script: """#!/bin/bash
              export CC=${CC}
              export ONLOAD_TREE=\$PWD/onload
              export ZF_DEVEL=1
              export ZF_RUN_UNSTABLE_TESTS=1
              export ZF_RUN_SLOW_TESTS=1
              export TEST_THREAD_NAME=zf
              make -k -C tcpdirect test
            """, returnStatus: true)
            if (rc != 0) {
              script.unstable("not all tests passed")
            }
          }
        },
      )
    }

    script.stage('Build packages') {
      utils.parallel(
        "build tarball": {
          script.node('unit-test-master') {
            script.deleteDir()
            script.unstash(tcpdirect_stash)
            script.unstash(onload_tarball_stash)
            script.sh 'ls -la $PWD'
            def CC = script.sh(script: 'ls -1d /opt/rh/devtoolset-{11,10,9,8}/root/usr/bin/cc $(which cc) 2>/dev/null | head -1',
                          returnStdout: true)
            script.sh """#!/bin/bash
              export CC=${CC}
              tcpdirect/scripts/zf_mkdist --version ${version_info.TCPDIRECT_VERSION} --name tcpdirect ${onload_tarball}
            """
            extractNotes("tcpdirect/scripts", "tcpdirect/build/tcpdirect-${version_info.TCPDIRECT_VERSION}.tgz")
            script.dir('tcpdirect/build/') {
              def tarball_prefix = "tcpdirect-${version_info.TCPDIRECT_VERSION}"
              def raw_tarball = "${tarball_prefix}.tgz"
              def raw_tarball_md5 = "${tarball_prefix}.tgz.md5"

              script.archiveArtifacts(artifacts: '*.tgz')
              script.archiveArtifacts(artifacts: '*.md5')
              script.archiveArtifacts(artifacts: '*.txt')

              package_locations['raw_tarball'] = raw_tarball
              package_locations['raw_tarball_md5'] = raw_tarball_md5

              script.stash name: 'raw_tarball', includes: raw_tarball
              script.stash name: 'raw_tarball_md5', includes: raw_tarball_md5

              script.sh 'rm *ReleaseNotes.txt'
              script.stash name: 'text_files', includes: '*.txt'
              def tarball_doxbox = "${tarball_prefix}-tarball-doxbox.zip"
              zip_and_archive_files(
                tarball_doxbox,
                '*.tgz',
                '*.md5',
                '*.txt'
              )
              package_locations['tarball_doxbox'] = tarball_doxbox
              script.stash name: 'tarball_doxbox', includes: tarball_doxbox
            }
          }
        },
        "build rpm": {
          script.node("publish-rpm-parallel") {
            script.deleteDir()
            script.unstash(tcpdirect_stash)
            String workspace = script.pwd()
            String outdir = "${workspace}/rpmbuild"
            script.sh(script: "mkdir -p ${outdir}")
            def safe_version_string = version_info.TCPDIRECT_VERSION.replace('-','_')
            script.sh "fakeroot tcpdirect/scripts/zf_make_official_srpm --version ${safe_version_string} --outdir ${outdir}"
            script.archiveArtifacts allowEmptyArchive: true, artifacts: 'rpmbuild/SRPMS/*.src.rpm', followSymlinks: false
            def srpm = "rpmbuild/SRPMS/tcpdirect-${safe_version_string}-1.src.rpm"
            package_locations['srpm'] = srpm
            script.stash name: 'srpm', includes: srpm
            script.sh "rm -rf ${outdir}"
          }
        },
        "build deb": {
          script.node("deb") {
            script.deleteDir()
            script.unstash(tcpdirect_stash)
            script.sh "tcpdirect/scripts/zf_mksrc --version ${version_info.TCPDIRECT_VERSION}"
            def source = "tcpdirect-${version_info.TCPDIRECT_VERSION}.tar.gz"
            script.stash name: 'tcpdirect-tar', includes: source
            package_locations['source'] = source
            script.stash name: 'source', includes: source
            script.archiveArtifacts allowEmptyArchive: true, artifacts: source, followSymlinks: false

            script.sh "tcpdirect/scripts/zf_make_official_deb --version ${version_info.TCPDIRECT_VERSION} ${source}"
            def deb_file = "tcpdirect-${version_info.TCPDIRECT_VERSION}-debiansource.tgz"
            script.sh "find . -name '*debiansource*.tgz' -exec cp {} ${deb_file} \\;"
            script.sh "ls -la ${deb_file}"
            package_locations['debiansource'] = deb_file
            script.stash name: 'debiansource', includes: deb_file
            script.archiveArtifacts allowEmptyArchive: true, artifacts: deb_file, followSymlinks: false
          }
        }
      )
    }

    // Create doxbox zips after all packages are built (needs text_files stash from tarball)
    script.stage('Create doxbox archives') {
      utils.parallel(
        "srpm doxbox": {
          script.node("publish-rpm-parallel") {
            script.deleteDir()
            script.unstash('srpm')
            script.unstash('text_files')
            def safe_version_string = version_info.TCPDIRECT_VERSION.replace('-','_')
            def srpm_file = "rpmbuild/SRPMS/tcpdirect-${safe_version_string}-1.src.rpm"
            def srpm_doxbox = "tcpdirect-${version_info.TCPDIRECT_VERSION}-srpm-doxbox.zip"
            zip_and_archive_files(
              srpm_doxbox,
              srpm_file,
              '*.txt'
            )
            package_locations['srpm_doxbox'] = srpm_doxbox
            script.stash name: 'srpm_doxbox', includes: srpm_doxbox
          }
        },
        "deb doxbox": {
          script.node("deb") {
            script.deleteDir()
            script.unstash('debiansource')
            script.unstash('text_files')
            def deb_doxbox_name = "tcpdirect-${version_info.TCPDIRECT_VERSION}-deb-doxbox.zip"
            zip_and_archive_files(
              deb_doxbox_name,
              '*debiansource.tgz',
              '*.txt'
            )
            package_locations['deb_doxbox'] = deb_doxbox_name
            script.stash name: 'deb_doxbox', includes: deb_doxbox_name
          }
        }
      )
    }
    return package_locations
  }
}

ZfPipeline create_pipeline(script, utils) {
  return new ZfPipeline(script, utils)
}

return this
