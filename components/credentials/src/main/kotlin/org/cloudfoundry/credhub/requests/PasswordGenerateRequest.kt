package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonProperty

class PasswordGenerateRequest : BaseCredentialGenerateRequest() {
    @JsonProperty("parameters")
    override var generationParameters: StringGenerationParameters? = null
        get() {
            if (field == null) {
                field = StringGenerationParameters()
            }
            return field
        }
}
