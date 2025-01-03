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
      long_revision = scmVars.GIT_COMMIT
      short_revision = scmVars.GIT_COMMIT.substring(0,12)
      version_info = readYaml(file: "tcpdirect/versions.yaml")
      echo "Got revision ${long_revision}"

      (tcpdirect_version_long, tcpdirect_version_short) = tcpdirect_version('tcpdirect', long_revision)

      stash(name: 'tcpdirect-src', includes: 'tcpdirect/**', useDefaultExcludes: true)

      onload_tarball = utils.getLatestOnloadTarball(version_info['products']['Onload']['version'])
      sh(script: "mkdir -p onload")
      sh(script: "tar xzf ${onload_tarball} -C onload --strip-components=1")
      stash(name: 'onload-tar', includes: onload_tarball, useDefaultExcludes: true)
      stash(name: 'onload-src', includes: 'onload/**', useDefaultExcludes: true)
    }
  }

  stage('Parallel builds') {
    utils.parallel(
      'build ndebug': {
        node('unit-test-master') {
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
        node('unit-test-master') {
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
        }
      },
      'run tests': {
        node('unit-test-master') {
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
  node('unit-test-master') {
    stage("Build TCPDirect Tarball") {
      sh 'rm -fr tcpdirect onload'
      unstash('tcpdirect-src')
      unstash('onload-tar')
      sh 'ls -lad $PWD'
      def CC = sh(script: 'ls -1d /opt/rh/devtoolset-{11,10,9,8}/root/usr/bin/cc $(which cc) 2>/dev/null | head -1',
                    returnStdout: true)
      sh """#!/bin/bash
        export CC=${CC}
        tcpdirect/scripts/zf_mkdist --version ${tcpdirect_version_long} --name tcpdirect ${onload_tarball}
      """
      extractNotes("tcpdirect/scripts", "tcpdirect/build/tcpdirect-${tcpdirect_version_long}.tgz")
      dir('tcpdirect/build/') {
        archiveArtifacts(artifacts: '*.tgz')
        archiveArtifacts(artifacts: '*.md5')
        archiveArtifacts(artifacts: '*.txt')
        sh 'rm *ReleaseNotes.txt'
        stash name: 'text_files', includes: '*.txt'
        zip_and_archive_files(
          "tcpdirect-${tcpdirect_version_long}-tarball-doxbox.zip",
          '*.tgz',
          '*.md5',
          '*.txt'
        )
      }
    }
  }

  stage('Build packages') {
    utils.parallel(
      "publish release rpm": {
        node("publish-rpm-parallel") {
          deleteDir()
          unstash('tcpdirect-src')
          String workspace = pwd()
          String outdir = "${workspace}/rpmbuild"
          sh(script: "mkdir -p ${outdir}")
          sh "fakeroot tcpdirect/scripts/zf_make_official_srpm --version ${tcpdirect_version_long} --outdir ${outdir}"
          archiveArtifacts allowEmptyArchive: true, artifacts: 'rpmbuild/SRPMS/*.src.rpm', followSymlinks: false
          unstash('text_files')
          zip_and_archive_files(
            "tcpdirect-${tcpdirect_version_long}-srpm-doxbox.zip",
            'rpmbuild/SRPMS/*.src.rpm',
            '*.txt'
          )
          sh "rm -rf ${outdir}"
        }
      },
      "publish deb": {
        node("deb") {
          stage('Create source tarball') {
            deleteDir()
            unstash('tcpdirect-src')
            sh "tcpdirect/scripts/zf_mksrc --version ${tcpdirect_version_long}"
            stash name: 'tcpdirect-tar', includes: "tcpdirect-${tcpdirect_version_long}.tar.gz"
            sh "mv tcpdirect-${tcpdirect_version_long}.tar.gz tcpdirect-source-${tcpdirect_version_long}.tar.gz"
            archiveArtifacts allowEmptyArchive: true, artifacts: "tcpdirect-source-${tcpdirect_version_long}.tar.gz", followSymlinks: false
          }
          stage('create deb') {
            deleteDir()
            unstash('tcpdirect-tar')
            unstash('tcpdirect-src')
            sh "tcpdirect/scripts/zf_make_official_deb --version ${tcpdirect_version_long} tcpdirect-${tcpdirect_version_long}.tar.gz"
            archiveArtifacts allowEmptyArchive: true, artifacts: '*debiansource.tgz', followSymlinks: false
            unstash('text_files')
            zip_and_archive_files(
              "tcpdirect-${tcpdirect_version_long}-deb-doxbox.zip",
              '*debiansource.tgz',
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
