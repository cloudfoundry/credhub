package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty

class UserGenerateRequest : BaseCredentialGenerateRequest() {
    @JsonProperty("parameters")
    private var passwordGenerationParameters: StringGenerationParameters? = StringGenerationParameters()

    @JsonProperty("value")
    private var value = UsernameValue()

    override val generationParameters: GenerationParameters?
        @JsonIgnore
        get() {
            if (value.username != null) {
                passwordGenerationParameters!!.username = value.username
            }
            return passwordGenerationParameters
        }

    val userName: String?
        get() = if (passwordGenerationParameters != null && passwordGenerationParameters!!.username != null) {
            passwordGenerationParameters!!.username
        } else value.username

    fun setGenerationParameters(generationParameters: StringGenerationParameters) {
        passwordGenerationParameters = generationParameters
    }

    fun setValue(value: UsernameValue) {
        this.value = value
    }
}
