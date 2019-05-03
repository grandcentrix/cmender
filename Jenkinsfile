pipeline {
    agent { dockerfile true }
    stages {
        stage('Build') {
            steps {
                echo 'building ...'
                sh './test.sh build'
            }
        }
        stage('Test') {
            steps {
                echo 'Testing..'
                sh './test.sh test'
            }
        }
    }
}
