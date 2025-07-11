/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Copyright 2025 Advanced Micro Devices, Inc. */

@Library('onload_jenkins_pipeline_lib')
import com.solarflarecom.onload.packaging.OnloadPackaging;
import com.solarflarecom.onload.scm.SCMManager
import com.solarflarecom.onload.utils.UtilityManager

import groovy.transform.Field

@Field
def packager = new OnloadPackaging(this);
@Field
def scmmanager = new SCMManager(this)
@Field
def utils = new UtilityManager(this)

def scmVars
boolean personal_job = ! env.JOB_NAME.startsWith('tcpdirect/')

def version_info
def onload_tarball

node('master') {
  stage('Checkout') {
    def pipeline_class
    def pipeline

    String onload_tarball_stash
    Map package_locations

    deleteDir()

    dir('tcpdirect') {
      scmVars = scmmanager.cloneGit(['branch' : REVISION], REPO)

      /* Groovy pipeline shenanigans */
      pipeline_class = load 'ci/pipeline.groovy'

      sh "pwd"
      sh "ls -l"

      /* Update version string in `versions.env` so that the correct value is
       * used for the `ZF_VERSION` macro */
      sh "sed -i versions.env -e 's/TCPDIRECT_VERSION=.*/TCPDIRECT_VERSION=${VERSION}/'"
    }

    pipeline = pipeline_class.create_pipeline(this, utils)

    sh "pwd"
    sh "ls -l"
 
    version_info = pipeline.get_version_info("tcpdirect")
    // Explicity update the version string so that patch release are as expected
    version_info.TCPDIRECT_VERSION = VERSION
    stash(name: 'tcpdirect-src', includes: 'tcpdirect/**', useDefaultExcludes: true)

    dir('onload') {
      scmVars = scmmanager.cloneGit(['branch' : ONLOAD_REVISION], ONLOAD_REPO)
    }
    stash(name: 'onload-src', includes: 'onload/**', useDefaultExcludes: true)
    (onload_tarball_stash, package_locations) = packager.buildTarball(ONLOAD_REPO, '', ONLOAD_REVISION, VERSION)
    onload_tarball = package_locations['raw_tarball']
    unstash(onload_tarball_stash)
    echo "onload_tarball_stash=${onload_tarball_stash}, package_locations={$package_locations}, onload_tarball=${onload_tarball}"
    sh "ls -la"
    stash(name: 'onload-tar', includes: onload_tarball, useDefaultExcludes: true)

    pipeline.doPipeline('tcpdirect-src',
                        'onload-src',
                        'onload-tar',
                        onload_tarball,
                        version_info)
  }
}
