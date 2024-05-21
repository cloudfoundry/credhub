package org.cloudfoundry.credhub.credential

import com.fasterxml.jackson.annotation.JsonAutoDetect
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonProperty.Access.READ_ONLY
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.utils.EmptyStringToNull
import org.cloudfoundry.credhub.validators.RequireAnyOf
import java.util.Objects

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

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other == null || javaClass != other.javaClass) {
            return false
        }
        val that = other as SshCredentialValue?
        return publicKey == that!!.publicKey &&
            privateKey == that.privateKey &&
            publicKeyFingerprint == that.publicKeyFingerprint
    }

    override fun hashCode(): Int {
        return Objects.hash(publicKey, privateKey, publicKeyFingerprint)
    }
}
