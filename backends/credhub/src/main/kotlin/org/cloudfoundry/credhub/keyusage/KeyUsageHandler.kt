package org.cloudfoundry.credhub.keyusage

interface KeyUsageHandler {
    fun getKeyUsage(): Map<String, Long>
}
