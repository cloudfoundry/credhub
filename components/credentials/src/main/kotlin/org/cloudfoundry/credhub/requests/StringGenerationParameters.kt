package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonInclude.Include.NON_DEFAULT
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonProperty.Access
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException
import org.cloudfoundry.credhub.generators.PassayStringCredentialGenerator
import java.util.Objects

@JsonInclude(NON_DEFAULT)
class StringGenerationParameters : GenerationParameters() {

    // Value Parameters
    @JsonProperty(access = Access.WRITE_ONLY)
    var length: Int = PassayStringCredentialGenerator.DEFAULT_LENGTH

    var username: String? = null

    var excludeLower: Boolean = false
    var excludeNumber: Boolean = false
    var excludeUpper: Boolean = false
    var includeSpecial: Boolean = false

    @JsonIgnore
    fun isValid(): Boolean {
        return !(
            !includeSpecial &&
                excludeNumber &&
                excludeUpper &&
                excludeLower
            )
    }

    fun isExcludeLower(): Boolean {
        return excludeLower
    }

    fun isExcludeNumber(): Boolean {
        return excludeNumber
    }

    fun isExcludeUpper(): Boolean {
        return excludeUpper
    }

    fun isIncludeSpecial(): Boolean {
        return includeSpecial
    }

    override fun validate() {
        if (!isValid()) {
            throw ParameterizedValidationException(ErrorMessages.EXCLUDES_ALL_CHARSETS)
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }

        if (other == null || javaClass != other.javaClass) {
            return false
        }

        val that = other as StringGenerationParameters?
        return excludeLower == that!!.excludeLower &&
            excludeNumber == that.excludeNumber &&
            excludeUpper == that.excludeUpper &&
            includeSpecial == that.includeSpecial &&
            length == that.length &&
            username == that.username
    }

    override fun hashCode(): Int {
        return Objects.hash(length, username, excludeLower, excludeNumber, excludeUpper, includeSpecial)
    }
}
