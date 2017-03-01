# CredHub 

The CredHub server manages secrets like passwords, certificates, ssh keys, rsa keys, strings 
(arbitrary values) and CAs. CredHub provides a REST API to get, set, or generate and securely store
such secrets.
 
* [CredHub Tracker](https://www.pivotaltracker.com/n/projects/1977341)
 
See additional repos for more info:

* [credhub-cli](https://github.com/cloudfoundry-incubator/credhub-cli) :     command line interface for credhub
* [credhub-acceptance-tests](https://github.com/cloudfoundry-incubator/credhub-acceptance-tests) : integration tests written in Go.
* [credhub-release](https://github.com/pivotal-cf/credhub-release) : BOSH release of CredHub server **[Currently private - Coming Soon]**

## Development Notes

CredHub is intended to be deployed by BOSH using `credhub-release`. Consequently, this repository is _not intended to be directly deployable_. 

Launching in production directly using the `bootRun` target is **unsafe** as you will launch with a `dev` profile.

### Configuration

Configuration for the server is spread across the `application*.yml` files.

* Configuration shared by all environments (dev, test or BOSH-deployed) is in `application.yml`. 
* Development-specific configuration is placed in `application-dev.yml`. This includes a JWT key intended for development use only.
* Per-database configuration is placed in `application-dev-h2.yml`,`application-dev-mysql.yml` and `application-dev-postgres.yml`. For convenience, these per-database profiles include the `dev` profile.

By default, CredHub launches with the `dev-h2` and `dev` profiles enabled.

### Starting the server with different databases

#### H2 (the default)

H2 datasource configuration is in `application-dev-h2.yml`.

```sh
./start_server.sh
```

#### PostgreSQL

Postgres datasource configuration is in `application-dev-postgres.yml`.

Before development, you'll need to create the target database.

```sh
createdb credhub
```

Then to run in development mode with Postgres

```sh
./start_server.sh -Dspring.profiles.active=dev-postgres
```

#### MySQL

MySQL datasource configuration is in `application-dev-mysql.yml`.

Log into your MySQL server. Create a database `credhub` with privileges granted to `root`.

Then to run in development mode with MySQL

```sh
./start_server.sh -Dspring.profiles.active=dev-mysql
```

### Running tests with different databases

Testing with different databases requires you to set a system property with the profile corresponding to your desired database. For example, to test with H2, you'll need to run the tests with the `-Dspring.profiles.active=unit-test-h2` profile.

During development, it is helpful to set up different IntelliJ testing profiles that use the following VM Options:

- `-ea -Dspring.profiles.active=unit-test-h2` for testing with H2
- `-ea -Dspring.profiles.active=unit-test-mysql` for testing with MySQL
- `-ea -Dspring.profiles.active=unit-test-postgres` for testing with Postgres

