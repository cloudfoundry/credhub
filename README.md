# <div align="center"><img src="docs/images/logo.png" alt="CredHub"></div>

[![slack.cloudfoundry.org](https://slack.cloudfoundry.org/badge.svg)](https://slack.cloudfoundry.org)

CredHub manages credentials like passwords, certificates, certificate authorities, ssh keys, rsa keys and arbitrary values (strings and JSON blobs). CredHub provides a CLI and API to get, set, generate and securely store such credentials.

* [Documentation](docs/)
* [CredHub API Docs](https://docs.cloudfoundry.org/api/credhub/)
* [CredHub Tracker](https://www.pivotaltracker.com/n/projects/1977341)

CredHub is intended to be deployed by [BOSH](https://bosh.io) using the [credhub-release](https://github.com/pivotal/credhub-release) BOSH release. This repository is for development and is **not intended to be directly deployable**.

Additional repos:

* [credhub-cli](https://github.com/cloudfoundry-incubator/credhub-cli): command line interface for credhub
* [credhub-release](https://github.com/pivotal/credhub-release): BOSH release of CredHub server
* [credhub-acceptance-tests](https://github.com/cloudfoundry-incubator/credhub-acceptance-tests): integration tests written in Go.

# Contributing to CredHub

The Cloud Foundry team uses GitHub and accepts contributions via [pull request](https://help.github.com/articles/using-pull-requests).

## Contributor License Agreement

Follow these steps to make a contribution to any of our open source repositories:

1. Ensure that you have completed our CLA Agreement for
  [individuals](https://www.cloudfoundry.org/pdfs/CFF_Individual_CLA.pdf) or
  [corporations](https://www.cloudfoundry.org/pdfs/CFF_Corporate_CLA.pdf).

1. Set your name and email (these should match the information on your submitted CLA)

        git config --global user.name "Firstname Lastname"
        git config --global user.email "your_email@example.com"

## Reporting a Vulnerability

We strongly encourage people to report security vulnerabilities privately to our security team before disclosing them in a public forum.

Please note that the e-mail address below should only be used for reporting undisclosed security vulnerabilities in open source Cloud Foundry codebases and managing the process of fixing such vulnerabilities. We cannot accept regular bug reports or other security-related queries at this address.

The e-mail address to use to contact the CFF Security Team is security@cloudfoundry.org.

Our public PGP key can be obtained from a public key server such as [pgp.mit.edu](https://pgp.mit.edu). Its fingerprint is: 3FC8 9AF3 940B E270 CF25  E122 9965 0006 EF9D C642. More information can be found at [cloudfoundry.org/security](https://cloudfoundry.org/security).

## General Workflow

1. Fork the repository
1. Create a feature branch (`git checkout -b <my_new_branch>`)
1. Make changes on your branch
1. Test your changes locally (see next section) and in a [bosh-lite](https://github.com/cloudfoundry/bosh-lite) or other test environment.
1. Push to your fork (`git push origin <my_new_branch>`) and submit a pull request

We favor pull requests with very small, single commits with a single purpose. Your pull request is much more likely to be accepted if it is small and focused with a clear message that conveys the intent of your change.

### Generating API Documentation

The CredHub API can generate API documentation by running its test suite (via Spring Rest Docs). CredHub API Documentation can be generated as follows:

```
./scripts/generate_documentation_snippets.sh
```

CredHub API documentation will be built as an html file in the CredHub backend gradle subproject build directory: `backends/credhub/build/asciidoc/html5`.

### Development Configuration

Launching in production directly using the `bootRun` target is **unsafe**, as you will launch with a `dev` profile, which has checked-in secret keys in `application-dev.yml`.

#### Dependency Graph

A dependency graph of project components (gradle subprojects) can be generated to better understand project organization. You will need graphviz installed on your system in order to generate the graph.

```
./gradlew dependenciesGraph
```

#### Generally

Configuration for the server is spread across the `application*.yml` files.

* Configuration shared by all environments (dev, test, or BOSH-deployed) is in `application.yml`.
* Development-specific configuration is in `application-dev.yml`. This includes:
  * A UAA URL intended for development use only,
  * A JWT public verification key for use with that UAA, and
  * two `dev-key`s intended for development use only.
* Per-database configuration is placed in `application-dev-h2.yml`,`application-dev-mysql.yml`, and `application-dev-postgres.yml`. For convenience, these per-database profiles include the `dev` profile.

By default, CredHub launches with the `dev-h2` and `dev` profiles enabled.

#### UAA and the JWT public signing key

CredHub requires a [UAA server](https://github.com/cloudfoundry/uaa) to manage authentication.

In `application-dev.yml` there are two relevant settings:

1. `auth-server.url`. This needs to point to a running UAA server (remote or BOSH-lite, it's up to you).
2. `security.oauth2.resource.jwt.key-value`. This is the public verification key, corresponding to a private JWT signing key held by your UAA server.

For convenience, the CredHub team runs a public UAA whose IP is in the default `application-dev.yml` manifest. The password grant values are `credhub`/`password` and the client credentials grant value are `credhub_client`/`secret`. This public UAA is for local development usage only! You will need to skip SSL validation in order to use it.

#### Running CredHub with local UAA

In order to run CredHub against a UAA running on your local machine, do the following:
1. Start a UAA with Docker: `docker run -d --mount type=bind,source=$PWD/config/uaa.yml,target=/uaa/uaa.yml -p 127.0.0.1:8080:8080 pcfseceng/uaa:latest`
1. Start CredHub server pointing at the local UAA: `./scripts/start_server.sh -Dspring.profiles.active=dev,dev-h2,dev-local-uaa`

For testing purposes, the local UAA bootstraps a user (username: `credhub`/ password: `password`) and a client (client ID:`credhub_client` / client secret:`secret`), with which you can access the local CredHub. For example:
```
# log into CredHub CLI using a UAA client; this client comes with permissions to access all CredHub credential paths (see `application-dev.yml` manifest)
credhub login -s https://localhost:9000 --client-name=credhub_client --client-secret=secret --skip-tls-validation
# log into CredHub CLI using a UAA user; this user does not come with permissions to CredHub credential paths (see `application-dev.yml` manifest)
credhub login -s https://localhost:9000 -u credhub -p password --skip-tls-validation
```

#### Starting the server with different databases

##### H2 (the default)

H2 datasource configuration is in `application-dev-h2.yml`.

```sh
./scripts/start_server.sh
```

##### PostgreSQL

Postgres datasource configuration is in `application-dev-postgres.yml`.

Before development, you'll need to create the target database.

A local Postgres server with docker can be started as follows:
```
docker run --name postgres-server \
   --env POSTGRES_USER=pivotal \
   --env POSTGRES_HOST_AUTH_METHOD=trust \
   --detach \
   --publish 5432:5432 \
   postgres:15
```

```sh
createdb credhub_dev
```

Then to run in development mode with Postgres

```sh
./scripts/start_server.sh -Dspring.profiles.active=dev,dev-postgres
```

##### MySQL

MySQL datasource configuration is in `application-dev-mysql.yml`.

Log into your MySQL server and create databases `credhub_dev` and `credhub_test` with privileges granted to `root`.

```shell
mysql -u root
create database credhub_test;
create database credhub_dev;
```

If you're on a Mac using Homebrew and you run into a problem where you install MySQL and it isn't running (i.e., `mysql -u root` errors with a socket error), you may need to uninstall mysql, delete the `/usr/local/var/mysql` directory (*Warning: this will delete all local MySQL data!*), and then reinstall MySQL.

Alternatively, you can also start a local MySQL server with docker:
```
docker run \
  --name mysql-server \
  --env MYSQL_ALLOW_EMPTY_PASSWORD='yes' \
  --env MYSQL_ROOT_HOST='%' \
  --publish 3306:3306 \
  --detach \
  "mysql:8.0"
```    

Then to run in development mode with MySQL:

```sh
./scripts/start_server.sh -Dspring.profiles.active=dev,dev-mysql
```

#### Debugging the server

To load JDWP agent for credhub jvm debugging, start the server as follows:
```sh
./scripts/start_server.sh -Pdebug=true
```

You can then attach your debugger to port 5005 of the jvm process.

To suspend the server start-up until the debugger is attached (useful for
debugging start-up code), start the server as follows:
```sh
./scripts/start_server.sh -Pdebugs=true
```

#### Running tests with different databases

Testing with different databases requires you to set a system property with the profile corresponding to your desired database. For example, to test with H2, you'll need to run the tests with the `-Dspring.profiles.active=unit-test-h2` profile.

During development, it is helpful to set up different IntelliJ testing profiles that use the following VM Options:

- `-ea -Dspring.profiles.active=unit-test-h2` for testing with H2
- `-ea -Dspring.profiles.active=unit-test-mysql` for testing with MySQL
- `-ea -Dspring.profiles.active=unit-test-postgres` for testing with Postgres

### Testing with the CLI and Acceptance Tests

#### Using the CLI locally

After having pulled the [credhub-cli](https://github.com/cloudfoundry-incubator/credhub-cli) repo, run `make`, and then run the following command to target your locally running CredHub instance:

```shell
build/credhub login -s https://localhost:9000 --client-name=credhub_client --client-secret=secret --skip-tls-validation
```

#### Running the Acceptance Tests

First, be sure to pull and compile the [credhub-cli](https://github.com/cloudfoundry-incubator/credhub-cli), as described above.

Make sure your development server is running. When it starts up for the first time, it will create a server CA and server certificate for SSL, as well as a trusted client CA for testing mutual TLS authentication. These will be located in `src/test/resources` relative to the `credhub` repository.

Pull [credhub-acceptance-tests](https://github.com/cloudfoundry-incubator/credhub-acceptance-tests) and run:

```shell
CREDENTIAL_ROOT=/path/to/credhub/repo/plus/src/test/resources ./scripts/run_tests.sh
```

Assuming it works, that will generate some test client certificates for testing mutual TLS (in `certs/` in the acceptance test directory) and run the acceptance test suite against your locally running credhub server.

### Cleaning up orphaned encrypted_value records
To clean up orphaned `encrypted_value` records from CredHub version 2.12.70 and
earlier (https://github.com/cloudfoundry/credhub/issues/231), follow the steps decribed in
[Cleaning up orphaned encrypted_value records](docs/orphaned-encryption-value-cleanup.md).
