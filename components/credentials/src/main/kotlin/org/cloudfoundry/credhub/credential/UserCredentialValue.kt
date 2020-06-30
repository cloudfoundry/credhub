package org.cloudfoundry.credhub.credential

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonProperty.Access.READ_ONLY
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import org.apache.commons.codec.digest.Crypt
import org.cloudfoundry.credhub.CryptSaltFactory
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.utils.EmptyStringToNull
import java.util.Objects
import javax.validation.constraints.NotEmpty

class UserCredentialValue : CredentialValue {
    @JsonDeserialize(using = EmptyStringToNull::class)
    var username: String? = null
    @NotEmpty(message = ErrorMessages.MISSING_PASSWORD)
    var password: String? = null
    @get:JsonIgnore
    var salt: String? = null

    constructor() : super() {}

    constructor(username: String?, password: String?, salt: String?) : super() {
        this.username = username
        this.password = password
        this.salt = salt
    }

    @JsonIgnore
    fun getOrGenerateSalt(): String? {
        if (salt == null) {
            salt = CryptSaltFactory().generateSalt(password)
        }

        return salt
    }

    @JsonProperty(value = "password_hash", access = READ_ONLY)
    fun getPasswordHash(): String = Crypt.crypt(password!!, getOrGenerateSalt())

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other == null || javaClass != other.javaClass) {
            return false
        }
        val that = other as UserCredentialValue?
        return Objects.equals(username, that!!.username) &&
            Objects.equals(password, that.password) &&
            Objects.equals(salt, that.salt)
    }

    override fun hashCode(): Int {
        return Objects.hash(username, password, salt)
    }
}
