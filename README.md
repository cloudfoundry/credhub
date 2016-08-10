# PCF Credential Manager
=========================
This "credhub" server helps manage secrets like passwords, certificates, and CAs,
offering a REST API for access to get/set/generate such secrets.
 
Credhub is intended to live within a Bosh Director, providing
 real credentials to the Bosh Director that it can substitute for 
 variable references.  This preserves security by obviating the need to check into git such credentials,
 within a Bosh manifest.

See additional repos for more info:

* cm-cli :     command line interface for credhub, coded in golang
* cm-release : provides wrapper around credhub server so that bosh director can use it as a release within the director itself
* sec-eng-deployment-credential-manager : cloud formation and bosh-init manifest template
* sec-eng-ci : concourse pipelines, including credential-manager.yml
* cred-hub-acceptance-tests : integration tests written in golang.

In order to init a Bosh Director that will contain the latest Credhub, you must have cloned the above repos into your ~/workspace directory.
The latest code, including any changes you want to test, should be in ~/workspace/sec-eng-credential-manager.
You must also have installed /usr/local/bin/aws with ```brew install awscli```.

If you haven't pulled the latest versions of the above repos recently, do it now. You need the latest version of the deploy_credhub.sh
script, so you need to pull sec-eng-deployment-credential-manager. You need the latest BOSH release config, so you need to pull cm-release.

In order to get the latest Credential Manager code into the release,

```
cd ~/workspace/cm-release
rm -rf dev_releases/credhub/*  # This step can be skipped if you've never run "bosh create release"
./scripts/update
```

To package and deploy that release, do the following:
```
cd ~/workspace/sec-eng-deployment-credential-manager
scripts/deploy_credhub.sh --dev
```

To debug while running on a VM:

* Make sure that TCP port 49151 allows inbound connections. This probably means changing an AWS security group. 
* Deploy the code you want to debug
* ssh into the VM
* cd /var/vcap/jobs/credhub
* sudo monit unmonitor credhub
* If credhub is running, kill the process
* sudo vi bin/ctl and add these flags: -Xdebug -Xnoagent -Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=49151
* sudo bin/ctl start

* In IntelliJ, create a run configuration of type "Remote" with the IP address of your VM and port number 49151
* Click the "Debug" button.