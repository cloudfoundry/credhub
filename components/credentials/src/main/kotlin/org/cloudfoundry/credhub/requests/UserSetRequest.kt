package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonProperty
import java.util.Objects
import javax.validation.Valid
import javax.validation.constraints.NotNull
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.credential.UserCredentialValue

class UserSetRequest : BaseCredentialSetRequest<UserCredentialValue?>() {
    @NotNull(message = ErrorMessages.MISSING_VALUE)
    @Valid
    @JsonProperty("value")
    var userValue: UserCredentialValue? = null
    override val generationParameters: GenerationParameters?
        get() = null

    override val credentialValue: UserCredentialValue?
        get() {
            return userValue
        }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other == null || javaClass != other.javaClass) {
            return false
        }
        val that = other as UserSetRequest?
        return Objects.equals(userValue, that!!.userValue)
    }

    override fun hashCode(): Int {
        return Objects.hash(userValue)
    }
}
