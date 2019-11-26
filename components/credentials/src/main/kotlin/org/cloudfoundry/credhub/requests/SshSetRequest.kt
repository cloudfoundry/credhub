package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonProperty
import java.util.Objects
import javax.validation.Valid
import javax.validation.constraints.NotNull
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.credential.SshCredentialValue

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

    override fun equals(o: Any?): Boolean {
        if (this === o) {
            return true
        }
        if (o == null || javaClass != o.javaClass) {
            return false
        }
        val that = o as SshSetRequest?
        return sshKeyValue == that!!.sshKeyValue
    }

    override fun hashCode(): Int {
        return Objects.hash(sshKeyValue)
    }
}
