package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty

class RsaGenerateRequest : BaseCredentialGenerateRequest() {
    @JsonProperty("parameters")
    override var generationParameters: RsaGenerationParameters? = null
        @JsonIgnore
        get() {
            if (field == null) {
                field = RsaGenerationParameters()
            }
            return field
        }
}
