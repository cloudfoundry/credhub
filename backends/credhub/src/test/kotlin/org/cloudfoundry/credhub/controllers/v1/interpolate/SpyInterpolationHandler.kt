package org.cloudfoundry.credhub.controllers.v1.interpolate

import org.cloudfoundry.credhub.interpolation.InterpolationHandler

class SpyInterpolationHandler : InterpolationHandler {
    lateinit var interpolatecredhubreferencesCalledwithServicesmap: Map<String, Any>
    lateinit var interpolatecredhubreferencesReturnsMap: Map<String, Any>

    override fun interpolateCredHubReferences(servicesMap: Map<String, Any>): Map<String, Any> {
        interpolatecredhubreferencesCalledwithServicesmap = servicesMap
        return interpolatecredhubreferencesReturnsMap
    }
}
