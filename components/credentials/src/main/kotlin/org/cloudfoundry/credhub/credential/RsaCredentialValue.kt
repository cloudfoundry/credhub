package org.cloudfoundry.credhub.credential

import com.fasterxml.jackson.annotation.JsonAutoDetect
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.utils.EmptyStringToNull
import org.cloudfoundry.credhub.validators.RequireAnyOf
import java.util.Objects

@RequireAnyOf(message = ErrorMessages.MISSING_RSA_SSH_PARAMETERS, fields = ["publicKey", "privateKey"])
@JsonAutoDetect
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

    override fun hashCode(): Int {
        return Objects.hash(publicKey, privateKey)
    }
}
