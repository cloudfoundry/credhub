# PCF Credential Manager
=========================
This "credhub" server helps manage secrets like passwords and certificates, 
offering rest apis for access to get/set/generate such secrets.
 
Credhub is intended to live within a Bosh Director, typically, providing
 real credentials to the Bosh Director that it can substitute for 
 variable references.  This preserves security by obviating the need to check into git such credentials,
 within a Bosh manifest.

See additional repos for more info:

* cm-cli :     command line interface for credhub, coded in golang
* cm-release : provides wrapper around credhub server so that bosh director can use it as a release within the director itself
* sec-eng-deployment-credential-manager : cloud formation and bosh-init manifest template
* sec-eng-ci : concourse pipelines, including credential-manager.yml
* cred-hub-acceptance-tests : integration tests written in golang.

In order to init a Bosh Director that will contain the latest Credhub, the following 
steps assume that the above repos are cloned as siblings in a ~/workspace/ directory:

* create cm release
    - cd cm-release
    - rm -rf dev_releases/credhub/*  # This step can be skipped if you've never run "bosh create release"
    - ./scripts/update
    - export SEC_ENG_CI_REPO=$HOME/workspace/sec-eng-ci
    - export RELEASE_DIR=$HOME/workspace/cm-release
    - bosh create release --with-tarball --name credhub --force --timestamp-version
* tell bosh about this new release
    - cd sec-eng-deployment-credential-manager/deployments/bosh
    - export RELEASE_PATH=/Users/pivotal/workspace/cm-release/dev_releases/credhub/credhub-1+dev.something.tgz
    - erb bosh-dev.yml.erb > bosh.yml # use bosh.yml.erb to release a 'real' director
    - edit any changes you like in bosh.yml, like adding an ssl certificate
* bosh-init deploy bosh.yml

