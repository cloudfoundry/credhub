# PCF CredHub
=========================
The CredHub server helps manage secrets like passwords, certificates, and CAs,
offering a REST API for access to get/set/generate such secrets.
 
See additional repos for more info:

* [credhub-cli](https://github.com/pivotal-cf/credhub-cli) :     command line interface for credhub
* [credhub-release](https://github.com/pivotal-cf/credhub-release) : BOSH release of CredHub server
* [cred-hub-acceptance-tests](https://github.com/pivotal-cf/cred-hub-acceptance-tests) : integration tests written in Go.

### To debug while running on a VM:

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