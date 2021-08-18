package org.cloudfoundry.credhub.views

import org.cloudfoundry.credhub.domain.CertificateCredentialVersion

class CertificateGenerationView : CertificateView {
    var durationOverridden: Boolean = false

    internal constructor() : super() /* Jackson */ {}

    constructor(version: CertificateCredentialVersion, concatenateCas: Boolean) : super(
        version,
        concatenateCas
    ) {
        durationOverridden = version.durationOverridden
    }
}