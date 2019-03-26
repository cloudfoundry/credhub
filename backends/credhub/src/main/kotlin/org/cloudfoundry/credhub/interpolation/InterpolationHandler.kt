package org.cloudfoundry.credhub.interpolation

interface InterpolationHandler {
    fun interpolateCredHubReferences(servicesMap: Map<String, Any>): Map<String, Any>
}
