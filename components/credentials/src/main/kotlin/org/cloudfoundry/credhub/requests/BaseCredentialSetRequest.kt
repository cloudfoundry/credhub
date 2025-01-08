package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonSubTypes
import com.fasterxml.jackson.annotation.JsonTypeInfo
import com.fasterxml.jackson.databind.annotation.JsonTypeIdResolver
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.constants.CredentialType
import org.cloudfoundry.credhub.credential.CredentialValue
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException
import java.util.Arrays

@JsonTypeInfo(use = JsonTypeInfo.Id.CUSTOM, property = "type", visible = true)
@JsonTypeIdResolver(SetRequestTypeIdResolver::class)
@JsonSubTypes(
    JsonSubTypes.Type(name = "password", value = PasswordSetRequest::class),
    JsonSubTypes.Type(name = "value", value = ValueSetRequest::class),
    JsonSubTypes.Type(name = "certificate", value = CertificateSetRequest::class),
    JsonSubTypes.Type(name = "json", value = JsonSetRequest::class),
    JsonSubTypes.Type(name = "ssh", value = SshSetRequest::class),
    JsonSubTypes.Type(name = "rsa", value = RsaSetRequest::class),
    JsonSubTypes.Type(name = "user", value = UserSetRequest::class),
)
abstract class BaseCredentialSetRequest<T : CredentialValue?> : BaseCredentialRequest() {
    @get:JsonIgnore
    abstract val credentialValue: T

    override fun validate() {
        super.validate()

        if (isInvalidTypeForSet(type!!)) {
            throw ParameterizedValidationException(ErrorMessages.INVALID_TYPE_WITH_SET_PROMPT)
        }

        if (name != null && name!!.length > 1024) {
            throw ParameterizedValidationException(ErrorMessages.NAME_HAS_TOO_MANY_CHARACTERS)
        }

        if (metadata != null && metadata!!.toString().length > 7000) {
            throw ParameterizedValidationException(ErrorMessages.METADATA_HAS_TOO_MANY_CHARACTERS)
        }
    }

    private fun isInvalidTypeForSet(type: String): Boolean =
        !Arrays.asList(*CredentialType.values()).contains(CredentialType.valueOf(type.uppercase()))
}
