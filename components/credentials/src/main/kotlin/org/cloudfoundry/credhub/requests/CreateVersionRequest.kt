package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonProperty
import jakarta.validation.Valid
import jakarta.validation.constraints.NotNull
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.credential.CertificateCredentialValue

class CreateVersionRequest {
    @NotNull(message = ErrorMessages.MISSING_VALUE)
    @Valid
    @JsonProperty("value")
    var value: CertificateCredentialValue? = null

    @JsonProperty("transitional")
    var isTransitional: Boolean = false

    constructor() : super() {
        // this needs to be there for jackson to be happy
    }

    constructor(value: CertificateCredentialValue, transitional: Boolean) : super() {
        this.value = value
        this.isTransitional = transitional
    }
}
