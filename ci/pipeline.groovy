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

  void doPipeline(String tcpdirect_stash,
                  String onload_stash,
                  String onload_tarball_stash,
                  String onload_tarball,
                  version_info)
  {
    script.stage('Parallel builds') {
      utils.parallel(
        'build ndebug': {
          script.node('unit-test-master') {
            script.sh 'rm -fr tcpdirect onload'
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
            script.sh 'rm -fr tcpdirect onload'
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
            script.sh 'rm -fr tcpdirect onload packetdrill-tcpdirect test-results'
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

    // This step produces release artifacts, must be run in controlled environment
    script.node('unit-test-master') {
      script.stage("Build TCPDirect Tarball") {
        script.sh 'rm -fr tcpdirect onload'
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
          script.archiveArtifacts(artifacts: '*.tgz')
          script.archiveArtifacts(artifacts: '*.md5')
          script.archiveArtifacts(artifacts: '*.txt')
          script.sh 'rm *ReleaseNotes.txt'
          script.stash name: 'text_files', includes: '*.txt'
          zip_and_archive_files(
            "tcpdirect-${version_info.TCPDIRECT_VERSION}-tarball-doxbox.zip",
            '*.tgz',
            '*.md5',
            '*.txt'
          )
        }
      }
    }

    script.stage('Build packages') {
      utils.parallel(
        "publish release rpm": {
          script.node("publish-rpm-parallel") {
            script.deleteDir()
            script.unstash(tcpdirect_stash)
            String workspace = script.pwd()
            String outdir = "${workspace}/rpmbuild"
            script.sh(script: "mkdir -p ${outdir}")
            def safe_version_string = version_info.TCPDIRECT_VERSION.replace('-','_')
            script.sh "fakeroot tcpdirect/scripts/zf_make_official_srpm --version ${safe_version_string} --outdir ${outdir}"
            script.archiveArtifacts allowEmptyArchive: true, artifacts: 'rpmbuild/SRPMS/*.src.rpm', followSymlinks: false
            script.unstash('text_files')
            zip_and_archive_files(
              "tcpdirect-${version_info.TCPDIRECT_VERSION}-srpm-doxbox.zip",
              'rpmbuild/SRPMS/*.src.rpm',
              '*.txt'
            )
            script.sh "rm -rf ${outdir}"
          }
        },
        "publish deb": {
          script.node("deb") {
            script.stage('Create source tarball') {
              script.deleteDir()
              script.unstash(tcpdirect_stash)
              script.sh "tcpdirect/scripts/zf_mksrc --version ${version_info.TCPDIRECT_VERSION}"
              script.stash name: 'tcpdirect-tar', includes: "tcpdirect-${version_info.TCPDIRECT_VERSION}.tar.gz"
              script.sh "mv tcpdirect-${version_info.TCPDIRECT_VERSION}.tar.gz tcpdirect-source-${version_info.TCPDIRECT_VERSION}.tar.gz"
              script.archiveArtifacts allowEmptyArchive: true, artifacts: "tcpdirect-source-${version_info.TCPDIRECT_VERSION}.tar.gz", followSymlinks: false
            }
            script.stage('create deb') {
              script.deleteDir()
              script.unstash('tcpdirect-tar')
              script.unstash(tcpdirect_stash)
              script.sh "tcpdirect/scripts/zf_make_official_deb --version ${version_info.TCPDIRECT_VERSION} tcpdirect-${version_info.TCPDIRECT_VERSION}.tar.gz"
              script.archiveArtifacts allowEmptyArchive: true, artifacts: '*debiansource.tgz', followSymlinks: false
              script.unstash('text_files')
              zip_and_archive_files(
                "tcpdirect-${version_info.TCPDIRECT_VERSION}-deb-doxbox.zip",
                '*debiansource.tgz',
                '*.txt'
              )
            }
          }
        }
      )
    }
  }
}

ZfPipeline create_pipeline(script, utils) {
  return new ZfPipeline(script, utils)
}

return this
