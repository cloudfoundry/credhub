package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.databind.JsonNode
import javax.validation.Validation
import javax.validation.constraints.NotEmpty
import javax.validation.constraints.Pattern
import org.apache.commons.lang3.StringUtils
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException

abstract class BaseCredentialRequest {

    @NotEmpty(message = ErrorMessages.MISSING_NAME)
    @Pattern.List(Pattern(regexp = HAS_NO_DOUBLE_SLASHES_AND_DOES_NOT_END_WITH_A_SLASH, message = ErrorMessages.Credential.INVALID_SLASH_IN_NAME), Pattern(regexp = ONLY_VALID_CHARACTERS_IN_NAME, message = ErrorMessages.Credential.INVALID_CHARACTER_IN_NAME), Pattern(regexp = IS_NOT_EMPTY, message = ErrorMessages.MISSING_NAME))
    var name: String? = null
        set(name) {
            field = StringUtils.prependIfMissing(name, "/")
        }
    var type: String? = null
        set(type) {
            field = type?.toLowerCase()
        }
    var metadata: JsonNode? = null

    abstract val generationParameters: GenerationParameters?

    open fun validate() {
        enforceJsr303AnnotationValidations()
    }

    private fun enforceJsr303AnnotationValidations() {
        val constraintViolations = Validation
            .buildDefaultValidatorFactory().validator.validate(this)
        for (constraintViolation in constraintViolations) {
            throw ParameterizedValidationException(constraintViolation.message)
        }
    }

    companion object {
        // '.', ':', '(', ')','[',']','+'
        const val HAS_NO_DOUBLE_SLASHES_AND_DOES_NOT_END_WITH_A_SLASH = "^(/|(?>(?:/?[^/]+))*)$"
        private const val ONLY_VALID_CHARACTERS_IN_NAME = "^[a-zA-Z0-9-_/.:,()\\[\\]+]*$"
        private const val IS_NOT_EMPTY = "^(.|\n){2,}$"
    }
}
