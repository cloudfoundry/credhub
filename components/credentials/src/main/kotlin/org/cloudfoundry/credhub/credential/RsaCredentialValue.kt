package org.cloudfoundry.credhub.credential

import com.fasterxml.jackson.annotation.JsonAutoDetect
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import java.util.Objects
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.utils.EmptyStringToNull
import org.cloudfoundry.credhub.validators.RequireAnyOf

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

    override fun equals(o: Any?): Boolean {
        if (this === o) {
            return true
        }
        if (o == null || javaClass != o.javaClass) {
            return false
        }
        val that = o as RsaCredentialValue?
        return Objects.equals(publicKey, that!!.publicKey) && Objects.equals(privateKey, that.privateKey)
    }

    override fun hashCode(): Int {
        return Objects.hash(publicKey, privateKey)
    }
}
