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

nm.slack_notify() {
  def pipeline_class
  def pipeline
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

        /* Groovy pipeline shenanigans */
        pipeline_class = load 'ci/pipeline.groovy'
      }

      pipeline = pipeline_class.create_pipeline(this, utils)

      version_info = pipeline.get_version_info("tcpdirect")
      echo "Got revision ${scmVars.GIT_COMMIT}"

      stash(name: 'tcpdirect-src', includes: 'tcpdirect/**', useDefaultExcludes: true)

      onload_tarball = utils.getLatestOnloadTarball(version_info.ONLOAD_VERSION)
      sh(script: "mkdir -p onload")
      sh(script: "tar xzf ${onload_tarball} -C onload --strip-components=1")
      stash(name: 'onload-tar', includes: onload_tarball, useDefaultExcludes: true)
      stash(name: 'onload-src', includes: 'onload/**', useDefaultExcludes: true)
    }
  }

  pipeline.doPipeline('tcpdirect-src',
                      'onload-src',
                      'onload-tar',
                      onload_tarball,
                      version_info)

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
