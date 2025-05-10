package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonProperty
import jakarta.validation.Valid
import jakarta.validation.constraints.NotNull
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.credential.SshCredentialValue
import java.util.Objects

class SshSetRequest : BaseCredentialSetRequest<SshCredentialValue?>() {
    @NotNull(message = ErrorMessages.MISSING_VALUE)
    @Valid
    @JsonProperty("value")
    var sshKeyValue: SshCredentialValue? = null

    override val generationParameters: GenerationParameters?
        get() = null

    override val credentialValue: SshCredentialValue?
        get() {
            return sshKeyValue
        }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other == null || javaClass != other.javaClass) {
            return false
        }
        val that = other as SshSetRequest?
        return sshKeyValue == that!!.sshKeyValue
    }

    override fun hashCode(): Int = Objects.hash(sshKeyValue)
}
