package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonSubTypes
import com.fasterxml.jackson.annotation.JsonTypeInfo
import com.fasterxml.jackson.databind.annotation.JsonTypeIdResolver
import com.google.common.collect.Lists.newArrayList
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.constants.CredentialWriteMode
import org.cloudfoundry.credhub.exceptions.InvalidModeException
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException
import java.util.Arrays
import java.util.Objects

@JsonTypeInfo(use = JsonTypeInfo.Id.CUSTOM, property = "type", visible = true, defaultImpl = DefaultCredentialGenerateRequest::class)
@JsonTypeIdResolver(GenerateRequestTypeIdResolver::class)
@JsonSubTypes(JsonSubTypes.Type(name = "password", value = PasswordGenerateRequest::class), JsonSubTypes.Type(name = "ssh", value = SshGenerateRequest::class), JsonSubTypes.Type(name = "rsa", value = RsaGenerateRequest::class), JsonSubTypes.Type(name = "certificate", value = CertificateGenerateRequest::class), JsonSubTypes.Type(name = "user", value = UserGenerateRequest::class))
abstract class BaseCredentialGenerateRequest : BaseCredentialRequest() {
    var overwrite: Boolean? = null
        set(overwrite) {
            field = overwrite
            rawOverwriteValue = overwrite.toString()
        }
    private var rawOverwriteValue: String? = null
    var mode: CredentialWriteMode? = null

    val isOverwrite: Boolean
        get() = if (this.overwrite == null) {
            false
        } else {
            this.overwrite!!
        }

    override fun validate() {
        super.validate()
        if (!isValidMode(this.mode)) {
            throw InvalidModeException(ErrorMessages.INVALID_MODE)
        }

        if (isInvalidCredentialType(type)) {
            throw ParameterizedValidationException(ErrorMessages.INVALID_TYPE_WITH_GENERATE_PROMPT)
        }

        if (isInvalidTypeForGeneration(type)) {
            throw ParameterizedValidationException(ErrorMessages.CANNOT_GENERATE_TYPE)
        }

        if (this.mode != null && rawOverwriteValue != null) {
            throw ParameterizedValidationException(ErrorMessages.OVERWRITE_AND_MODE_BOTH_PROVIDED)
        }

        if (generationParameters != null) {
            generationParameters?.validate()
        }

        if (name != null && name!!.length > 1024) {
            throw ParameterizedValidationException(ErrorMessages.NAME_HAS_TOO_MANY_CHARACTERS)
        }

        if (metadata != null && metadata!!.toString().length > 7000) {
            throw ParameterizedValidationException(ErrorMessages.METADATA_HAS_TOO_MANY_CHARACTERS)
        }
    }

    private fun isValidMode(mode: CredentialWriteMode?): Boolean {
        if (mode == null) {
            return true
        }

        val modes = Arrays.asList(*CredentialWriteMode.values())

        for (writeMode in modes) {
            if (writeMode == mode) {
                return true
            }
        }

        return false
    }

    private fun isInvalidCredentialType(type: String?): Boolean {
        return !newArrayList("password", "certificate", "rsa", "ssh", "value", "json", "user").contains(type)
    }

    private fun isInvalidTypeForGeneration(type: String?): Boolean {
        return !newArrayList("password", "certificate", "rsa", "ssh", "user").contains(type)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other == null || javaClass != other.javaClass) {
            return false
        }
        val that = other as BaseCredentialGenerateRequest?
        return this.overwrite == that!!.overwrite &&
            rawOverwriteValue == that.rawOverwriteValue &&
            mode === that.mode
    }

    override fun hashCode(): Int {
        return Objects.hash(this.overwrite, rawOverwriteValue, mode)
    }
}
