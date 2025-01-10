/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Copyright 2020-2024 Advanced Micro Devices, Inc. */

@Library('onload_jenkins_pipeline_lib')
import com.solarflarecom.onload.notifications.NotificationManager
import com.solarflarecom.onload.utils.UtilityManager
import com.solarflarecom.onload.autosmoke.AutosmokeManager
import com.solarflarecom.onload.test.TestManager
import com.solarflarecom.onload.scm.SCMManager


import groovy.transform.Field

def orgfilesRepo = 'ssh://git@github.com/Xilinx-CNS/tcpdirect_jenkins_orgfiles.git'

@Field
def nm = new NotificationManager(this)
@Field
def utils = new UtilityManager(this)
def am = new AutosmokeManager(this)
@Field
def tm = new TestManager(this)
@Field
def scmmanager = new SCMManager(this)

Properties get_version_info(String tcpdirect_dir) {
  String versionsFileContents = readFile("${tcpdirect_dir}/versions.env")
  Properties props = new Properties()
  props.load(new StringReader(versionsFileContents))
  if( ! props.containsKey("TCPDIRECT_VERSION") ) {
    error("Failed to extract TCPDirect version")
  }
  props.TCPDIRECT_VERSION = "${props.TCPDIRECT_VERSION}.${env.BUILD_NUMBER}"
  return props
}

void extractNotes(String scripts_dir, String tarball) {
  sh "${scripts_dir}/tcpdirect_misc/tcpdirect-extract-notes ${tarball}"
}

void zip_and_archive_files(String zipfile, String ... files_to_zip) {
  def cmd = [ 'zip', '-j', "'${zipfile}'" ]
  cmd += files_to_zip.collect { f -> "${f}" }
  sh(cmd.join(' '))
  archiveArtifacts(zipfile)
}

nm.slack_notify() {
  def scmVars
  boolean personal_job = ! env.JOB_NAME.startsWith('tcpdirect/')

  def version_info
  def onload_tarball

  // grab all the sources and stash them for other stages
  // this should be the only bit that deals with git
  // unless we want to push something
  node('master') {
    def workspace = pwd()
    echo "Job name: ${env.JOB_NAME} ${env.NODE_NAME} ${workspace}"

    stage('Checkout') {
      // remove the folders we would be using
      sh 'rm -fr tcpdirect onload packetdrill-tcpdirect'
      // checkout tcpdirect in subfolder
      dir('tcpdirect') {
        scmVars = scmmanager.cloneGit(scm)
      }
      version_info = get_version_info("tcpdirect")
      echo "Got revision ${scmVars.GIT_COMMIT}"

      stash(name: 'tcpdirect-src', includes: 'tcpdirect/**', useDefaultExcludes: true)

      onload_tarball = utils.getLatestOnloadTarball(version_info.ONLOAD_VERSION)
      sh(script: "mkdir -p onload")
      sh(script: "tar xzf ${onload_tarball} -C onload --strip-components=1")
      stash(name: 'onload-tar', includes: onload_tarball, useDefaultExcludes: true)
      stash(name: 'onload-src', includes: 'onload/**', useDefaultExcludes: true)
    }
  }

  stage('Parallel builds') {
    utils.parallel(
      'build ndebug': {
        node('unit-test-parallel') {
          sh 'rm -fr tcpdirect onload'
          unstash('tcpdirect-src')
          unstash('onload-src')
          sh 'ls -lad $PWD'
          def CC = sh(script: 'ls -1d /opt/rh/devtoolset-{11,10,9,8}/root/usr/bin/cc $(which cc) 2>/dev/null | head -1',
                      returnStdout: true)
          sh """#!/bin/bash
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
        // This step produces artifacts, so let's have it build with predictable environment
        node('build && centos7') {
          sh 'rm -fr tcpdirect onload'
          unstash('tcpdirect-src')
          unstash('onload-src')
          sh 'ls -lad $PWD'
          def CC = sh(script: 'ls -1d /opt/rh/devtoolset-{11,10,9,8}/root/usr/bin/cc $(which cc) 2>/dev/null | head -1',
                      returnStdout: true)
          sh """#!/bin/bash
            export CC=${CC}
            export ONLOAD_TREE=\$PWD/onload
            export NDEBUG=1
            export ZF_DEVEL=1
            make -C tcpdirect shim
          """
          dir('tcpdirect/build/gnu_x86_64-zf-devel/lib/') {
            stash(
              name: "zf-libzf_sockets",
              includes: 'libzf_sockets.so',
            )
          }
          
        }
      },
      'run tests': {
        node('unit-test-parallel') {
          sh 'rm -fr tcpdirect onload packetdrill-tcpdirect test-results'
          unstash('tcpdirect-src')
          unstash('onload-src')
          sh 'ls -lad $PWD'
          def CC = sh(script: 'ls -1d /opt/rh/devtoolset-{11,10,9,8}/root/usr/bin/cc $(which cc) 2>/dev/null | head -1',
                      returnStdout: true)
          dir('test-results') { // ensure folder exists
          }
          // Makefiles do not support gcov build yet
          def rc = sh(script: """#!/bin/bash
            export CC=${CC}
            export ONLOAD_TREE=\$PWD/onload
            export ZF_DEVEL=1
	    export ZF_RUN_UNSTABLE_TESTS=1
	    export ZF_RUN_SLOW_TESTS=1
            export TEST_THREAD_NAME=zf
            make -k -C tcpdirect test
          """, returnStatus: true)
          if (rc != 0) {
            unstable("not all tests passed")
          }
        }
      },
    )
  }

  // This step produces release artifacts, must be run in controlled environment
  node('build && centos7') {
    stage("Build TCPDirect Tarball") {
      sh 'rm -fr tcpdirect onload'
      unstash('tcpdirect-src')
      unstash('onload-tar')
      sh 'ls -lad $PWD'
      def CC = sh(script: 'ls -1d /opt/rh/devtoolset-{11,10,9,8}/root/usr/bin/cc $(which cc) 2>/dev/null | head -1',
                    returnStdout: true)
      sh """#!/bin/bash
        export CC=${CC}
        tcpdirect/scripts/zf_mkdist --version ${version_info.TCPDIRECT_VERSION} --name tcpdirect ${onload_tarball}
      """
      extractNotes("tcpdirect/scripts", "tcpdirect/build/tcpdirect-${version_info.TCPDIRECT_VERSION}.tgz")
      dir('tcpdirect/build/') {
        archiveArtifacts(artifacts: '*.tgz')
        archiveArtifacts(artifacts: '*.md5')
        archiveArtifacts(artifacts: '*.txt')
        sh 'rm *ReleaseNotes.txt'
        stash name: 'text_files', includes: '*.txt'
        zip_and_archive_files(
          "tcpdirect-${version_info.TCPDIRECT_VERSION}-tarball-doxbox.zip",
          '*.tgz',
          '*.md5',
          '*.txt'
        )
        stash(
          name: "tcpdirect-release-tarball",
          includes: "tcpdirect-${version_info.TCPDIRECT_VERSION}.tgz",
        )
      }
      stash(name: "tcpdirect-build-artifacts", includes: "tcpdirect/build/artifacts/**")
    }

    stage('Archive unstripped binaries') {
      sh "tcpdirect/scripts/zf_make_tarball --version ${version_info.TCPDIRECT_VERSION} --unstripped"
      dir('tcpdirect/build/') {
        archiveArtifacts artifacts: '*unstripped*.tgz', allowEmptyArchive: true
        sh 'rm -f *unstripped*.tgz'
      }
    }
  }

  stage('Build packages') {
    utils.parallel(
      "publish release rpm": {
        node("publish-rpm-parallel") {
          deleteDir()
          unstash('tcpdirect-release-tarball')
          unstash('tcpdirect-src')
          sh "tcpdirect/scripts/zf_make_official_srpm tcpdirect-${version_info.TCPDIRECT_VERSION}.tgz --version ${version_info.TCPDIRECT_VERSION}"
          archiveArtifacts allowEmptyArchive: true, artifacts: '*.src.rpm', followSymlinks: false
          unstash('text_files')
          zip_and_archive_files(
          "tcpdirect-${version_info.TCPDIRECT_VERSION}-srpm-doxbox.zip",
          '*.src.rpm',
          '*.txt'
        )
        }
      },
      "publish release deb": {
        node("deb") {
          stage('stage installation') {
            deleteDir()
            unstash('tcpdirect-release-tarball')
            sh "tar xvzf tcpdirect-${version_info.TCPDIRECT_VERSION}.tgz"
            sh "tcpdirect-${version_info.TCPDIRECT_VERSION}/scripts/zf_install --packaging --dest-dir staging/usr"
            stash(name: "tcpdirect-staged-installation", includes: "staging/**")
          }
          stage('build deb') {
            deleteDir()
            unstash('tcpdirect-staged-installation')
            unstash('tcpdirect-src')
            sh "tcpdirect/scripts/zf_make_official_deb --version ${version_info.TCPDIRECT_VERSION} staging"
            archiveArtifacts allowEmptyArchive: true, artifacts: '*.deb', followSymlinks: false
            unstash('text_files')
            zip_and_archive_files(
              "tcpdirect-${version_info.TCPDIRECT_VERSION}-deb-doxbox.zip",
              '*.deb',
              '*.txt'
            )
          }
        }
      }
    )
  }

  // this uses 'runbench' node internally
  am.doAutosmoke(version_info.ONLOAD_REPO_SOURCE, version_info.ONLOAD_VERSION,
                 'last_known_good/' + version_info.ONLOAD_VERSION,
                 orgfilesRepo, personal_job, true, am.sourceUrl(), env.BRANCH_NAME)
}



/*
 ** Local variables:
 ** groovy-indent-offset: 2
 ** indent-tabs-mode: nil
 ** fill-column: 75
 ** tab-width: 2
 ** End:
 */
