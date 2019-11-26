package org.cloudfoundry.credhub.credential

import com.fasterxml.jackson.annotation.JsonAutoDetect
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonProperty.Access.READ_ONLY
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import java.util.Objects
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.utils.EmptyStringToNull
import org.cloudfoundry.credhub.validators.RequireAnyOf

@RequireAnyOf(message = ErrorMessages.MISSING_RSA_SSH_PARAMETERS, fields = ["publicKey", "privateKey"])
@JsonAutoDetect
class SshCredentialValue : CredentialValue {

    @JsonDeserialize(using = EmptyStringToNull::class)
    var publicKey: String? = null
    @JsonDeserialize(using = EmptyStringToNull::class)
    var privateKey: String? = null
    @get:JsonProperty(access = READ_ONLY)
    var publicKeyFingerprint: String? = null

    constructor() : super() {}

    constructor(publicKey: String?, privateKey: String?, publicKeyFingerprint: String?) : super() {
        this.publicKey = publicKey
        this.privateKey = privateKey
        this.publicKeyFingerprint = publicKeyFingerprint
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) {
            return true
        }
        if (o == null || javaClass != o.javaClass) {
            return false
        }
        val that = o as SshCredentialValue?
        return publicKey == that!!.publicKey &&
            privateKey == that.privateKey &&
            publicKeyFingerprint == that.publicKeyFingerprint
    }

    override fun hashCode(): Int {
        return Objects.hash(publicKey, privateKey, publicKeyFingerprint)
    }
}
