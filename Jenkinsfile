pipeline {
    agent none
    options {
        ansiColor('xterm')
        timeout(time: 30, unit: 'MINUTES')
        timestamps()
    }
    stages {
        stage('build') {
            agent { label 'master' }
            steps {
                script {
                    /*
                    GITHUB_API = 'https://api.github.com/repos/oajara'

                    withCredentials([usernamePassword(credentialsId: 'oscar-test-up', usernameVariable: 'PR_BUILDER_USER', passwordVariable: 'PR_BUILDER_TOKEN')]) {
                        def prDetails = readJSON(text: httpRequest(url: GITHUB_API + '/brave-core-crx-packager/pulls:' + CHANGE_BRANCH, customHeaders: [[name: 'Authorization', value: 'token ' + PR_BUILDER_TOKEN]]).content)[0]
                        SKIP = prDetails.labels.count { label -> label.name.equalsIgnoreCase('CI/skip') }.equals(1)
                    }

                    if (SKIP) {
                        echo "Aborting build as PRs are either in draft or have a skip label (CI/skip)"
                        currentBuild.result = 'ABORTED'
                        return
                    }

                    for (build in Jenkins.instance.getItemByFullName(JOB_NAME).builds) {
                        if (build.isBuilding() && build.getNumber() < BUILD_NUMBER.toInteger()) {
                            echo 'Aborting older running build ' + build
                            build.doStop()
                        }
                    }
                    */

                    sh "git fetch origin master"
                    def modifiedFiles = sh(
                        script: "git diff --name-only origin/master",
                        returnStdout: true
                    ).trim().split("\n")
        
                    def filePath = 'scripts/packageTorClient.js'
                    if (!modifiedFiles.contains(filePath)) {
                        print("No changes detected in ${filePath}")
                        currentBuild.result = 'SUCCESS'
                    } else {
                        def PIPELINE_NAME = "brave-core-ext-tor-client-update-publish-dev"
                        def params = [string(name: "BRANCH", value: BRANCH), bool(name: "UPLOAD", value: false)]
                        print("Changes detected in ${filePath}. Running ${PIPELINE_NAME}")
                        currentBuild.result = build(job: PIPELINE_NAME, parameters: params, wait: true, propagate: false).result
                    }
                }
            }
        }
    }
}