package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty

class SshGenerateRequest : BaseCredentialGenerateRequest() {
    @JsonProperty("parameters")
    override var generationParameters: SshGenerationParameters? = null
        @JsonIgnore
        get() {
            if (field == null) {
                field = SshGenerationParameters()
            }
            return field
        }
}
