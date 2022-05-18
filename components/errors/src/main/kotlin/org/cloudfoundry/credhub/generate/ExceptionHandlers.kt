package org.cloudfoundry.credhub.generate

import com.fasterxml.jackson.core.JsonParseException
import com.fasterxml.jackson.databind.JsonMappingException
import com.fasterxml.jackson.databind.exc.InvalidFormatException
import com.fasterxml.jackson.databind.exc.InvalidTypeIdException
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException
import com.jayway.jsonpath.InvalidJsonException
import org.apache.logging.log4j.LogManager
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.exceptions.InvalidModeException
import org.cloudfoundry.credhub.exceptions.InvalidPermissionException
import org.cloudfoundry.credhub.exceptions.InvalidPermissionOperationException
import org.cloudfoundry.credhub.exceptions.InvalidQueryParameterException
import org.cloudfoundry.credhub.exceptions.InvalidRemoteAddressException
import org.cloudfoundry.credhub.exceptions.KeyNotFoundException
import org.cloudfoundry.credhub.exceptions.MalformedCertificateException
import org.cloudfoundry.credhub.exceptions.MalformedPrivateKeyException
import org.cloudfoundry.credhub.exceptions.MaximumSizeException
import org.cloudfoundry.credhub.exceptions.MissingCertificateException
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException
import org.cloudfoundry.credhub.exceptions.PermissionAlreadyExistsException
import org.cloudfoundry.credhub.exceptions.PermissionDoesNotExistException
import org.cloudfoundry.credhub.exceptions.PermissionException
import org.cloudfoundry.credhub.exceptions.PermissionInvalidPathAndActorException
import org.cloudfoundry.credhub.exceptions.ReadOnlyException
import org.cloudfoundry.credhub.exceptions.UnreadableCertificateException
import org.cloudfoundry.credhub.views.ResponseError
import org.springframework.core.Ordered.HIGHEST_PRECEDENCE
import org.springframework.core.annotation.Order
import org.springframework.http.HttpStatus
import org.springframework.http.converter.HttpMessageNotReadableException
import org.springframework.web.HttpMediaTypeNotSupportedException
import org.springframework.web.HttpRequestMethodNotSupportedException
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.MissingServletRequestParameterException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestControllerAdvice
import java.io.InvalidObjectException
import java.text.MessageFormat
import javax.servlet.http.HttpServletResponse

@RestControllerAdvice
@Order(HIGHEST_PRECEDENCE)
@SuppressWarnings("PMD.TooManyMethods", "PMD.CouplingBetweenObjects")
class ExceptionHandlers {

    private val LOGGER = LogManager.getLogger(ExceptionHandlers::class.java)

    @ExceptionHandler(EntryNotFoundException::class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    fun handleNotFoundException(e: EntryNotFoundException): ResponseError {
        return constructClientError(e.message)
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException::class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    fun handleRequestMethodNotSupportedException(e: HttpRequestMethodNotSupportedException) {
    }

    @ExceptionHandler(PermissionException::class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    fun handlePermissionException(error: PermissionException): ResponseError {
        return constructError(error.message)
    }

    @ExceptionHandler(JsonMappingException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleJsonMappingException(e: JsonMappingException): ResponseError {
        for (reference in e.path) {
            if ("operations" == reference.fieldName) {
                return constructError(ErrorMessages.Permissions.INVALID_OPERATION)
            }
        }

        return badRequestResponse()
    }

    @ExceptionHandler(InvalidQueryParameterException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleInvalidParameterException(e: InvalidQueryParameterException): ResponseError {
        return constructError(e.message, e.invalidQueryParameter)
    }

    @ExceptionHandler(MissingServletRequestParameterException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleMissingParameterException(e: MissingServletRequestParameterException): ResponseError {
        return constructError(ErrorMessages.MISSING_QUERY_PARAMETER, e.parameterName)
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleHttpMediaTypeNotSupportedException(e: HttpMediaTypeNotSupportedException): ResponseError {

        var errorMessage = ""

        val contentType = e.contentType
        if (null != contentType) {
            errorMessage = contentType.toString()
        }

        return constructError(ErrorMessages.INVALID_CONTENT_TYPE, errorMessage)
    }

    @ExceptionHandler(JsonParseException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleJsonMappingException(e: JsonParseException): ResponseError {
        return badRequestResponse()
    }

    @ExceptionHandler(ParameterizedValidationException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleParameterizedValidationException(
        exception: ParameterizedValidationException
    ): ResponseError {
        return constructError(exception.message, exception.getParameters())
    }

    @ExceptionHandler(UnrecognizedPropertyException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleUnrecognizedPropertyException(exception: UnrecognizedPropertyException): ResponseError {
        return constructError(ErrorMessages.INVALID_JSON_KEY, exception.propertyName)
    }

    @ExceptionHandler(MethodArgumentNotValidException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleMethodArgumentNotValidException(exception: MethodArgumentNotValidException): ResponseError {

        val message = exception.bindingResult.allErrors[0].defaultMessage

        return if (message != null) {
            constructError(message)
        } else constructError(exception.message)
    }

    @ExceptionHandler(InvalidRemoteAddressException::class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    fun handleInvalidRemoteAddressException(): ResponseError {
        return constructError(ErrorMessages.INVALID_REMOTE_ADDRESS)
    }

    @ExceptionHandler(ReadOnlyException::class)
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    fun handleReadOnlyException(): ResponseError {
        return constructError(ErrorMessages.READ_ONLY_MODE)
    }

    @ExceptionHandler(UnreadableCertificateException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleUnreadableCertificateException(): ResponseError {
        return constructError(ErrorMessages.UNREADABLE_CERTIFICATE)
    }

    @ExceptionHandler(MissingCertificateException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleMissingCertificateException(): ResponseError {
        return constructError(ErrorMessages.MISSING_CERTIFICATE)
    }

    @ExceptionHandler(MalformedCertificateException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleMalformedCertificateException(): ResponseError {
        return constructError(ErrorMessages.INVALID_CERTIFICATE_VALUE)
    }

    @ExceptionHandler(InvalidJsonException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleInputNotReadableException(exception: Exception): ResponseError {

        val cause = if (exception.cause == null) exception else exception.cause

        if (cause is UnrecognizedPropertyException) {
            return constructError(ErrorMessages.INVALID_JSON_KEY, cause.propertyName)
        } else if (cause is InvalidTypeIdException || cause is JsonMappingException && cause.message?.contains("missing property 'type'") == true) {
            return constructError(ErrorMessages.INVALID_TYPE_WITH_SET_PROMPT)
        }
        return badRequestResponse()
    }

    @ExceptionHandler(InvalidPermissionOperationException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleIncorrectAclOperation(e: InvalidPermissionOperationException): ResponseError {
        return constructError(e.message)
    }

    @ExceptionHandler(InvalidPermissionException::class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    fun handleInvalidPermission(e: InvalidPermissionException): ResponseError {
        return constructError(e.message)
    }

    @ExceptionHandler(InvalidModeException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleInvalidMode(e: InvalidModeException): ResponseError {
        return constructError(e.message)
    }

    @ExceptionHandler(PermissionAlreadyExistsException::class)
    @ResponseStatus(HttpStatus.CONFLICT)
    fun handleIncorrectAclOperation(e: PermissionAlreadyExistsException): ResponseError {
        return constructError(e.message)
    }

    @ExceptionHandler(PermissionDoesNotExistException::class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    fun handlePermissionDoesNotExist(e: PermissionDoesNotExistException): ResponseError {
        return constructError(e.message)
    }

    @ExceptionHandler(PermissionInvalidPathAndActorException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handlePermissionHasInvalidPathAndActor(e: PermissionInvalidPathAndActorException): ResponseError {
        return constructError(e.message)
    }

    @ExceptionHandler(KeyNotFoundException::class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    fun handleKeyNotFoundException(e: KeyNotFoundException): ResponseError {
        return constructError(e.message)
    }

    @ExceptionHandler(InvalidObjectException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleInvalidTypeAccess(exception: InvalidObjectException): ResponseError {
        return constructError(exception.message)
    }

    @ExceptionHandler(MaximumSizeException::class)
    @ResponseStatus(HttpStatus.PAYLOAD_TOO_LARGE)
    fun handleMaximumSizeException(exception: MaximumSizeException): ResponseError {
        return constructError(ErrorMessages.EXCEEDS_MAXIMUM_SIZE)
    }

    @ExceptionHandler(MalformedPrivateKeyException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleMalformedPrivateKey(exception: MalformedPrivateKeyException): ResponseError {
        val responseError = constructError(ErrorMessages.MALFORMED_PRIVATE_KEY)
        val exceptionMessage = exception.message
        if (exceptionMessage != null) {
            val error = responseError.error
            return ResponseError(arrayOf(error, exceptionMessage).joinToString(" "))
        } else {
            return responseError
        }
    }

    @ExceptionHandler(NotImplementedError::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleNotImplementedError(exception: NotImplementedError): ResponseError {
        return constructError(ErrorMessages.RemoteBackend.NOT_IMPLEMENTED)
    }

    @ExceptionHandler(HttpMessageNotReadableException::class, InvalidFormatException::class)
    fun handleIncorrectOperation(e: Exception, response: HttpServletResponse): ResponseError {
        val cause = if (e.cause == null) e else e.cause
        response.status = HttpStatus.UNPROCESSABLE_ENTITY.value()

        if (cause is UnrecognizedPropertyException) {
            return constructError(ErrorMessages.INVALID_JSON_KEY, cause.propertyName)
        } else if (cause is InvalidTypeIdException || cause is JsonMappingException && cause.message?.contains("missing property 'type'") == true) {
            return constructError(ErrorMessages.INVALID_TYPE_WITH_SET_PROMPT)
        } else if (cause is JsonMappingException) {
            for (reference in cause.path) {
                if ("operations" == reference.fieldName) {
                    return constructError(ErrorMessages.Permissions.INVALID_OPERATION)
                }
            }
        } else if (cause is InvalidFormatException) {
            for (
                reference in cause
                    .path
            ) {
                if ("operations" == reference.fieldName) {
                    return constructError(ErrorMessages.Permissions.INVALID_OPERATION)
                }
            }
        }
        response.status = HttpStatus.BAD_REQUEST.value()
        return badRequestResponse()
    }

    private fun badRequestResponse(): ResponseError {
        return constructError(ErrorMessages.BAD_REQUEST)
    }

    private fun constructError(error: String?): ResponseError {
        LOGGER.error(error)
        return constructResponseError(error)
    }

    private fun constructError(error: String?, vararg args: String): ResponseError {
        val messageFormat = MessageFormat(error)
        val message = messageFormat.format(args)
        LOGGER.error(message)
        return ResponseError(message)
    }

    private fun constructError(error: String?, args: Array<Any>): ResponseError {
        val messageFormat = MessageFormat(error)
        val message = messageFormat.format(args)
        LOGGER.error(message)
        return ResponseError(message)
    }

    private fun constructClientError(error: String?): ResponseError {
        LOGGER.info(error)
        return constructResponseError(error)
    }

    private fun constructResponseError(error: String?): ResponseError {
        val message = MessageFormat.format(error)
        return ResponseError(message)
    }
}
