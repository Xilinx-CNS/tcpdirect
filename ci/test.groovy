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


String[] tcpdirect_version(String tcpdirect_dir, String changeset, String product="TCPDirect") {
  def long_version, short_version
  if( product == 'developer-build' ) {
    long_version = '0' + changeset
    short_version = long_version.take(13)
  } else {
    def version_info = readYaml(file: "${tcpdirect_dir}/versions.yaml")
    if( ! version_info.containsKey('products') ) {
      error("Invalid versions file - no products")
    }

    if( ! version_info['products'].containsKey(product) ) {
      error("Cannot find product [${product}] - cannot build")
    }

    if( ! version_info['products'][product].containsKey('version') ) {
      error("Product [${product}] has no version - cannot build")
    }

    long_version = version_info['products'][product]['version']
    short_version = long_version
  }
  return ["${long_version}.${env.BUILD_NUMBER}", "${short_version}.${env.BUILD_NUMBER}"]
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

  def long_revision
  def short_revision
  String tcpdirect_version_short, tcpdirect_version_long
  def version_info


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
      long_revision = scmVars.GIT_COMMIT
      short_revision = scmVars.GIT_COMMIT.substring(0,12)
      version_info = readYaml(file: "tcpdirect/versions.yaml")
      echo "Got revision ${long_revision}"

      (tcpdirect_version_long, tcpdirect_version_short) = tcpdirect_version('tcpdirect', long_revision)

      stash(name: 'tcpdirect-src', includes: 'tcpdirect/**', useDefaultExcludes: true)

      dir('onload') {
        // This just uses the raw checkout from onload, do we want to use a mkdist tarball?
        Map optionsMap = ['branch':version_info['products']['Onload']['version']]
        scmmanager.cloneGit(optionsMap, version_info['products']['Onload']['repo_source'])
      }
      stash(name: 'onload-src', includes: 'onload/**', useDefaultExcludes: true)

      dir('packetdrill-tcpdirect') {
        Map optionsMap = ['branch':version_info['products']['Packetdrill']['version']]
        scmmanager.cloneGit(optionsMap, version_info['products']['Packetdrill']['repo_source'])
      }
      stash(name: 'packetdrill-tcpdirect-src', includes: 'packetdrill-tcpdirect/**', useDefaultExcludes: true)
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
          unstash('packetdrill-tcpdirect-src')
          sh 'ls -lad $PWD'
          def CC = sh(script: 'ls -1d /opt/rh/devtoolset-{11,10,9,8}/root/usr/bin/cc $(which cc) 2>/dev/null | head -1',
                      returnStdout: true)
          dir('test-results') { // ensure folder exists
          }
          // Makefiles do not support gcov build yet
          sh """#!/bin/bash
            export CC=${CC}
            export ONLOAD_TREE=\$PWD/onload
            export ZF_DEVEL=1
            export TEST_THREAD_NAME=zf
            export TEST_RESULTS=\$PWD/test-results
            # export GCOV=1
            export UT_OUTPUT=\$PWD/test-results
            make -k -C tcpdirect test
          """
          stash(
            name: "junit-zf",
            includes: 'test-results/**',
          )
        }
      },
    )
  }

  node('master') {
    // this does not need any specific node
    stage('Generate test report') {
      sh 'rm -fr test-results'
      unstash("junit-zf")
      junit('test-results/**')
      currentBuild.description = tm.getTestResultString()
    }
  }

  // This step produces release artifacts, must be run in controlled environment
  node('build && centos7') {
    stage("Build TCPDirect Tarball") {
      sh 'rm -fr tcpdirect onload'
      unstash('tcpdirect-src')
      unstash('onload-src')
      sh 'ls -lad $PWD'
      def CC = sh(script: 'ls -1d /opt/rh/devtoolset-{11,10,9,8}/root/usr/bin/cc $(which cc) 2>/dev/null | head -1',
                    returnStdout: true)
      sh """#!/bin/bash
        export CC=${CC}
        export ONLOAD_TREE=\$PWD/onload
        tcpdirect/scripts/zf_mkdist_build --onload_tree \$ONLOAD_TREE
        tcpdirect/scripts/zf_make_tarball --version ${tcpdirect_version_long}
      """
      extractNotes("tcpdirect/scripts", "tcpdirect/build/tcpdirect-${tcpdirect_version_long}.tgz")
      dir('tcpdirect/build/') {
        archiveArtifacts(artifacts: '*.tgz')
        archiveArtifacts(artifacts: '*.md5')
        archiveArtifacts(artifacts: '*.txt')
        stash name: 'text_files', includes: '*.txt'
        zip_and_archive_files(
          "tcpdirect-${tcpdirect_version_long}-tarball-doxbox.zip",
          '*.tgz',
          '*.md5',
          '*.txt'
        )
        stash(
          name: "tcpdirect-release-tarball",
          includes: "tcpdirect-${tcpdirect_version_long}.tgz",
        )
      }
      stash(name: "tcpdirect-build-artifacts", includes: "tcpdirect/build/artifacts/**")
    }

    stage('Archive unstripped binaries') {
      sh "tcpdirect/scripts/zf_make_tarball --version ${tcpdirect_version_long} --unstripped"
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
          sh "tcpdirect/scripts/zf_make_official_srpm tcpdirect-${tcpdirect_version_long}.tgz --version ${tcpdirect_version_long}"
          archiveArtifacts allowEmptyArchive: true, artifacts: '*.src.rpm', followSymlinks: false
          unstash('text_files')
          zip_and_archive_files(
          "tcpdirect-${tcpdirect_version_long}-srpm-doxbox.zip",
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
            sh "tar xvzf tcpdirect-${tcpdirect_version_long}.tgz"
            sh "tcpdirect-${tcpdirect_version_long}/scripts/zf_install --packaging --dest-dir staging/usr"
            stash(name: "tcpdirect-staged-installation", includes: "staging/**")
          }
          stage('build deb') {
            deleteDir()
            unstash('tcpdirect-staged-installation')
            unstash('tcpdirect-src')
            sh "tcpdirect/scripts/zf_make_official_deb --version ${tcpdirect_version_long} staging"
            archiveArtifacts allowEmptyArchive: true, artifacts: '*.deb', followSymlinks: false
            unstash('text_files')
            zip_and_archive_files(
              "tcpdirect-${tcpdirect_version_long}-deb-doxbox.zip",
              '*.deb',
              '*.txt'
            )
          }
        }
      }
    )
  }

  // this uses 'runbench' node internally
  am.doAutosmoke(version_info['products']['Onload']['repo_source'], version_info['products']['Onload']['version'],
                 'last_known_good/' + version_info['products']['Onload']['version'],
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
