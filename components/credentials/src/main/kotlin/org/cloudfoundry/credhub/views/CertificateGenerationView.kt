package org.cloudfoundry.credhub.views

import org.cloudfoundry.credhub.domain.CertificateCredentialVersion

class CertificateGenerationView : CertificateView {
    var durationOverridden: Boolean = false
    var durationUsed: Int = 0

    internal constructor() : super() {}

    constructor(version: CertificateCredentialVersion, concatenateCas: Boolean) : super(
        version,
        concatenateCas,
    ) {
        durationOverridden = version.durationOverridden
        durationUsed = version.durationUsed
    }
}
