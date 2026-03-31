package org.cloudfoundry.credhub.requests

import jakarta.validation.Valid
import jakarta.validation.constraints.NotNull
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.credential.CertificateCredentialValue

class CreateVersionRequest(
    @field:NotNull(message = ErrorMessages.MISSING_VALUE)
    @field:Valid
    var value: CertificateCredentialValue? = null,
    var transitional: Boolean = false,
)
