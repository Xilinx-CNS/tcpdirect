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

    // This step produces release artifacts, must be run in controlled environment
    script.node('unit-test-master') {
      script.stage("Build TCPDirect Tarball") {
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
        script.stash(name: "tcpdirect-build-artifacts", includes: "tcpdirect/build/artifacts/**")
      }

      script.stage('Archive unstripped binaries') {
        script.sh "tcpdirect/scripts/zf_make_tarball --version ${version_info.TCPDIRECT_VERSION} --unstripped"
        script.dir('tcpdirect/build/') {
          script.archiveArtifacts artifacts: '*unstripped*.tgz', allowEmptyArchive: true
          script.sh 'rm -f *unstripped*.tgz'
        }
      }
    }

    script.stage('Build packages') {
      utils.parallel(
        "build rpm": {
          script.node("publish-rpm-parallel") {
            script.deleteDir()
            script.unstash('raw_tarball')
            script.unstash(tcpdirect_stash)
            script.sh "tcpdirect/scripts/zf_make_official_srpm tcpdirect-${version_info.TCPDIRECT_VERSION}.tgz --version ${version_info.TCPDIRECT_VERSION}"
            script.archiveArtifacts allowEmptyArchive: true, artifacts: '*.src.rpm', followSymlinks: false
            def srpm = "tcpdirect-${version_info.TCPDIRECT_VERSION}-1.src.rpm"
            package_locations['srpm'] = srpm
            script.stash name: 'srpm', includes: srpm
          }
        },
        "build deb": {
          script.node("deb") {
            script.stage('stage installation') {
              script.deleteDir()
              script.unstash('raw_tarball')
              script.sh "tar xvzf tcpdirect-${version_info.TCPDIRECT_VERSION}.tgz"
              script.sh "tcpdirect-${version_info.TCPDIRECT_VERSION}/scripts/zf_install --packaging --dest-dir staging/usr"
              script.stash(name: "tcpdirect-staged-installation", includes: "staging/**")
            }
            script.stage('build deb') {
              script.deleteDir()
              script.unstash('tcpdirect-staged-installation')
              script.unstash(tcpdirect_stash)
              script.sh "tcpdirect/scripts/zf_make_official_deb --version ${version_info.TCPDIRECT_VERSION} staging"
              def deb_file = "tcpdirect_${version_info.TCPDIRECT_VERSION}-1_amd64.deb"
              package_locations['debiansource'] = deb_file
              script.stash name: 'debiansource', includes: deb_file
              script.archiveArtifacts allowEmptyArchive: true, artifacts: '*.deb', followSymlinks: false
            }
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
            def srpm_file = "tcpdirect-${version_info.TCPDIRECT_VERSION}-1.src.rpm"
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
              '*.deb',
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
