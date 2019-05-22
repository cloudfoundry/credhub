package org.cloudfoundry.credhub.keyusage

import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Service

@Service
@Profile("remote")
class RemoteKeyUsageHandler : KeyUsageHandler {
    override fun getKeyUsage(): Map<String, Long> {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }
}
