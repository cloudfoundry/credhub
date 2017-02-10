# CF CredHub 

The CredHub server manages secrets like passwords, certificates, ssh keys, rsa keys, strings 
(arbitrary values) and CAs. CredHub provides a REST API to get, set, or generate and securely store
such secrets.
 
See additional repos for more info:

* [credhub-cli](https://github.com/pivotal-cf/credhub-cli) :     command line interface for credhub
* [credhub-release](https://github.com/pivotal-cf/credhub-release) : BOSH release of CredHub server
* [credhub-acceptance-tests](https://github.com/pivotal-cf/credhub-acceptance-tests) : integration tests written in Go.

## Development Notes

### Starting the server

Start the app: `./start_server.sh`

### Running against different databases

CredHub supports MySql, Postgres, and H2. You can change which database is used by
adjusting the spring datasource values in the `application-dev.yml` file. Migrations 
should run automatically during application startup.

Testing with different databases requires you to set a system property with the profile 
corresponding to your desired database. For example, to test with H2, you'll need to run
the tests with the `-Dspring.profiles.active=unit-test-h2` profile. 

During development, it is helpful to set up different IntelliJ testing profiles that use
the following VM Options:

- `-ea -Dspring.profiles.active=unit-test-h2` for testing with H2
- `-ea -Dspring.profiles.active=unit-test-mysql` for testing with MySQL
- `-ea -Dspring.profiles.active=unit-test-postgres` for testing with Postgres

### To debug while running on a VM:

- Make sure that TCP port 49151 allows inbound connections. This probably means changing an AWS security group. 
- Deploy the code you want to debug
- ssh into the VM
- cd /var/vcap/jobs/credhub
- sudo monit unmonitor credhub
- If credhub is running, kill the process
- sudo vi bin/ctl and add these flags: -Xdebug -Xnoagent -Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=49151
- sudo bin/ctl start
- In IntelliJ, create a run configuration of type "Remote" with the IP address of your VM and port number 49151
- Click the "Debug" button.
