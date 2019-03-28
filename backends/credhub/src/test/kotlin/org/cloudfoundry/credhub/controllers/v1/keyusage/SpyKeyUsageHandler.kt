package org.cloudfoundry.credhub.controllers.v1.keyusage

import org.cloudfoundry.credhub.keyusage.KeyUsageHandler

class SpyKeyUsageHandler : KeyUsageHandler {

    lateinit var getKeyUsage__returns_results: Map<String, Long>
    override fun getKeyUsage(): Map<String, Long> {
        return getKeyUsage__returns_results
    }
}