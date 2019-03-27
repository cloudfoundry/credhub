package org.cloudfoundry.credhub.utils

interface VersionProvider {

    fun currentVersion(): String
}