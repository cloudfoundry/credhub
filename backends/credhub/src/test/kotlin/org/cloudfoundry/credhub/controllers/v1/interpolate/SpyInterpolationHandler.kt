package org.cloudfoundry.credhub.controllers.v1.interpolate

import org.cloudfoundry.credhub.interpolation.InterpolationHandler

class SpyInterpolationHandler : InterpolationHandler {

    lateinit var interpolateCredhubReferences__calledWith_servicesMap: Map<String, Any>
    lateinit var interpolateCredhubReferences__returns_map: Map<String, Any>
    override fun interpolateCredHubReferences(servicesMap: Map<String, Any>): Map<String, Any> {
        interpolateCredhubReferences__calledWith_servicesMap = servicesMap
        return interpolateCredhubReferences__returns_map
    }
}
