package org.cloudfoundry.credhub.credential

import com.fasterxml.jackson.annotation.JsonAutoDetect
import com.fasterxml.jackson.annotation.JsonPropertyOrder
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.utils.EmptyStringToNull
import org.cloudfoundry.credhub.validators.RequireAnyOf
import tools.jackson.databind.annotation.JsonDeserialize
import java.util.Objects

@RequireAnyOf(message = ErrorMessages.MISSING_RSA_SSH_PARAMETERS, fields = ["publicKey", "privateKey"])
@JsonAutoDetect
@JsonPropertyOrder("public_key", "private_key")
class RsaCredentialValue : CredentialValue {
    @JsonDeserialize(using = EmptyStringToNull::class)
    var publicKey: String? = null

    @JsonDeserialize(using = EmptyStringToNull::class)
    var privateKey: String? = null

    constructor() : super() {}

    constructor(publicKey: String?, privateKey: String?) : super() {
        this.publicKey = publicKey
        this.privateKey = privateKey
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other == null || javaClass != other.javaClass) {
            return false
        }
        val that = other as RsaCredentialValue?
        return Objects.equals(publicKey, that!!.publicKey) && Objects.equals(privateKey, that.privateKey)
    }

    override fun hashCode(): Int = Objects.hash(publicKey, privateKey)
}
