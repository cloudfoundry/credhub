# <div align="center"><img src="docs/images/logo.png" alt="CredHub"></div>

[![slack.cloudfoundry.org](https://slack.cloudfoundry.org/badge.svg)](https://slack.cloudfoundry.org)

CredHub manages credentials like passwords, certificates, certificate authorities, ssh keys, rsa keys and arbitrary values (strings and JSON blobs). CredHub provides a CLI and API to get, set, generate and securely store such credentials.

* [Documentation](docs/)
* [CredHub Tracker](https://www.pivotaltracker.com/n/projects/1977341)

CredHub is intended to be deployed by [BOSH](https://bosh.io) using the [credhub-release](https://github.com/pivotal-cf/credhub-release) BOSH release. This repository is for development and is **not intended to be directly deployable**.

Additional repos:

* [credhub-cli](https://github.com/cloudfoundry-incubator/credhub-cli): command line interface for credhub
* [credhub-release](https://github.com/pivotal-cf/credhub-release): BOSH release of CredHub server
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

### Development Configuration

Launching in production directly using the `bootRun` target is **unsafe**, as you will launch with a `dev` profile, which has checked-in secret keys in `application-dev.yml`.

#### Generally

Configuration for the server is spread across the `application*.yml` files.

* Configuration shared by all environments (dev, test, or BOSH-deployed) is in `application.yml`.
* Development-specific configuration is in `application-dev.yml`. This includes:
  * A UAA URL intended for development use only,
  * A JWT public verification key for use with that UAA, and
  * two `dev-key`s intended for development use only.
* Per-database configuration is placed in `application-dev-h2.yml`,`application-dev-mysql.yml`, and `application-dev-postgres.yml`. For convenience, these per-database profiles include the `dev` profile.

By default, CredHub launches with the `dev-h2` and `dev` profiles enabled.

#### Oracle JDK vs OpenJDK

CredHub relies on the JDK to have uncrippled cryptographic capability -- in the Oracle JDK, this requires the slightly deceptively named "Unlimited Strength Jurisdiction Policy".

By default, OpenJDK ships with "Unlimited Strength". Our credhub-release uses OpenJDK, and so inherits the full-strength capability.

But the Oracle JDK is often installed on workstations and does _not_ have the Unlimited Strength policy.

##### How can I tell?

If you see an error like `java.security.InvalidKeyException: Illegal key size`, you probably haven't installed the additional policy for the Oracle JDK. CredHub is trying to use 256-bit keys, but is being blocked by the default policy.

##### Resolving

Oracle makes the Unlimited Strength policy available for [separate download here](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html).

Assuming you are on OS X, you can then run:

```
unzip ~/Downloads/jce_policy-8.zip -d /tmp
sudo cp /tmp/UnlimitedJCEPolicyJDK8/*.jar "$(/usr/libexec/java_home)/jre/lib/security/"
```

You will need to restart CredHub locally for changes to take effect.

#### UAA and the JWT public signing key

CredHub requires a [UAA server](https://github.com/cloudfoundry/uaa) to manage authentication.

In `application-dev.yml` there are two relevant settings:

1. `auth-server.url`. This needs to point to a running UAA server (remote or BOSH-lite, it's up to you).
2. `security.oauth2.resource.jwt.key-value`. This is the public verification key, corresponding to a private JWT signing key held by your UAA server.

For convenience, the CredHub team runs a public UAA whose IP is in the default `application-dev.yml` manifest. The password grant values are `credhub`/`password` and the client credentials grant value are `credhub_client`/`secret`. This public UAA is for local development usage only! You will need to skip SSL validation in order to use it.

#### Running CredHub with local UAA

In order to run CredHub against a UAA running on your local machine, do the following:
1. Start a UAA with Docker: `docker run -d --mount type=bind,source=$PWD/config/uaa.yml,target=/uaa/uaa.yml -p 127.0.0.1:8080:8080 pcfseceng/uaa:latest`
1. Start CredHub server pointing at the local UAA: `./start_server.sh -Dspring.profiles.active=dev,dev-local-uaa`

#### Starting the server with different databases

##### H2 (the default)

H2 datasource configuration is in `application-dev-h2.yml`.

```sh
./start_server.sh
```

##### PostgreSQL

Postgres datasource configuration is in `application-dev-postgres.yml`.

Before development, you'll need to create the target database.

```sh
createdb credhub_dev
```

Then to run in development mode with Postgres

```sh
./start_server.sh -Dspring.profiles.active=dev,dev-postgres
```

##### MariaDB

MariaDB datasource configuration is in `application-dev-mysql.yml`.

Log into your MariaDB server and create databases `credhub_dev` and `credhub_test` with privileges granted to `root`.

```shell
mysql -u root
create database credhub_test;
create database credhub_dev;
```

If you're on a Mac using Homebrew and you run into a problem where you install MariaDB and it isn't running (i.e., `mysql -u root` errors with a socket error), you may need to uninstall mysql, delete the `/usr/local/var/mysql` directory (*Warning: this will delete all local mysql & mariadb data!*), and then reinstall mariadb.

Then to run in development mode with MariaDB:

```sh
./start_server.sh -Dspring.profiles.active=dev,dev-mysql
```

#### Running tests with different databases

Testing with different databases requires you to set a system property with the profile corresponding to your desired database. For example, to test with H2, you'll need to run the tests with the `-Dspring.profiles.active=unit-test-h2` profile.

During development, it is helpful to set up different IntelliJ testing profiles that use the following VM Options:

- `-ea -Dspring.profiles.active=unit-test-h2` for testing with H2
- `-ea -Dspring.profiles.active=unit-test-mysql` for testing with MariaDB
- `-ea -Dspring.profiles.active=unit-test-postgres` for testing with Postgres

### Testing with the CLI and Acceptance Tests

#### Using the CLI locally

After having pulled the [credhub-cli](https://github.com/cloudfoundry-incubator/credhub-cli) repo, run `make`, and then run the following command to target your locally running CredHub instance:

```shell
build/credhub login -s https://localhost:9000 -u credhub -p password --skip-tls-validation
```

#### Running the Acceptance Tests

First, be sure to pull and compile the [credhub-cli](https://github.com/cloudfoundry-incubator/credhub-cli), as described above.

Make sure your development server is running. When it starts up for the first time, it will create a server CA and server certificate for SSL, as well as a trusted client CA for testing mutual TLS authentication. These will be located in `src/test/resources` relative to the `credhub` repository.

Pull [credhub-acceptance-tests](https://github.com/cloudfoundry-incubator/credhub-acceptance-tests) and run:

```shell
CREDENTIAL_ROOT=/path/to/credhub/repo/plus/src/test/resources ./run_tests.sh
```

Assuming it works, that will generate some test client certificates for testing mutual TLS (in `certs/` in the acceptance test directory) and run the acceptance test suite against your locally running credhub server.

#### Setting up FindBugs in Intellij

1. Goto Preferences -> Plugins
1. Search for and install FindBugs
1. Goto Preferences -> Other Settings -> FindBugs-IDEA
1. Click on import button and import config/findbugs/findbugs-idea.xml
1. Click `+` under `Plugins` and select `Find Security Bugs`
1. Click on filters
1. Click `+` under `Exclude filter files` and select config/findbugs/findbugs-filter.xml
