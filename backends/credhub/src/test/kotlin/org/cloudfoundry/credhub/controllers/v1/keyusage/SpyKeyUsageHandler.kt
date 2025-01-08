package org.cloudfoundry.credhub.controllers.v1.keyusage

import org.cloudfoundry.credhub.keyusage.KeyUsageHandler

class SpyKeyUsageHandler : KeyUsageHandler {
    lateinit var keyusageReturnsMap: Map<String, Long>

    override fun getKeyUsage(): Map<String, Long> = keyusageReturnsMap
}
