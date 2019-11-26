package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonIgnore

class DefaultCredentialGenerateRequest : BaseCredentialGenerateRequest() {

    var parameters: Any? = null

    override val generationParameters: GenerationParameters?
        @JsonIgnore
        get() = null
}
