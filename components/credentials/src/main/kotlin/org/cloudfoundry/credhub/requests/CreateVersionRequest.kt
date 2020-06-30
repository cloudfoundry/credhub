package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonProperty
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.credential.CertificateCredentialValue
import javax.validation.Valid
import javax.validation.constraints.NotNull

class CreateVersionRequest {

    @NotNull(message = ErrorMessages.MISSING_VALUE)
    @Valid
    @JsonProperty("value")
    var value: CertificateCredentialValue? = null
    @JsonProperty("transitional")
    var isTransitional: Boolean = false

    constructor() : super() {
        /* this needs to be there for jackson to be happy */
    }

    constructor(value: CertificateCredentialValue, transitional: Boolean) : super() {
        this.value = value
        this.isTransitional = transitional
    }
}
