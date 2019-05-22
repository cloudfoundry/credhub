package org.cloudfoundry.credhub.interpolation

import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Service

@Service
@Profile("remote")
class RemoteInterpolationHandler : InterpolationHandler {
    override fun interpolateCredHubReferences(servicesMap: Map<String, Any>): Map<String, Any> {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }
}
