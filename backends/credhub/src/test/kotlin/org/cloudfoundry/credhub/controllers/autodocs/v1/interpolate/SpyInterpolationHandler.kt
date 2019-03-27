package org.cloudfoundry.credhub.controllers.autodocs.v1.interpolate

import org.cloudfoundry.credhub.interpolation.InterpolationHandler

class SpyInterpolationHandler : InterpolationHandler {

    lateinit var interpolateCredhubReferences__calledWithServicesMap: Map<String, Any>
    lateinit var interpolateCredhubReferences__returns_results: Map<String, Any>
    override fun interpolateCredHubReferences(servicesMap: Map<String, Any>): Map<String, Any> {
        interpolateCredhubReferences__calledWithServicesMap = servicesMap
        return interpolateCredhubReferences__returns_results
    }
}
