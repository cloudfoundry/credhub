package org.cloudfoundry.credhub.handlers;

import java.io.InvalidObjectException;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.fasterxml.jackson.databind.exc.InvalidTypeIdException;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import com.jayway.jsonpath.InvalidJsonException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.InvalidModeException;
import org.cloudfoundry.credhub.exceptions.InvalidPermissionException;
import org.cloudfoundry.credhub.exceptions.InvalidPermissionOperationException;
import org.cloudfoundry.credhub.exceptions.InvalidQueryParameterException;
import org.cloudfoundry.credhub.exceptions.InvalidRemoteAddressException;
import org.cloudfoundry.credhub.exceptions.KeyNotFoundException;
import org.cloudfoundry.credhub.exceptions.MalformedCertificateException;
import org.cloudfoundry.credhub.exceptions.MalformedPrivateKeyException;
import org.cloudfoundry.credhub.exceptions.MaximumSizeException;
import org.cloudfoundry.credhub.exceptions.MissingCertificateException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.exceptions.PermissionAlreadyExistsException;
import org.cloudfoundry.credhub.exceptions.PermissionDoesNotExistException;
import org.cloudfoundry.credhub.exceptions.PermissionException;
import org.cloudfoundry.credhub.exceptions.PermissionInvalidPathAndActorException;
import org.cloudfoundry.credhub.exceptions.ReadOnlyException;
import org.cloudfoundry.credhub.exceptions.UnreadableCertificateException;
import org.cloudfoundry.credhub.views.ResponseError;

import static org.springframework.core.Ordered.HIGHEST_PRECEDENCE;

@RestControllerAdvice
@Order(HIGHEST_PRECEDENCE)
@SuppressWarnings({
  "PMD.TooManyMethods",
  "PMD.CouplingBetweenObjects",
})
public class ExceptionHandlers {

  private final MessageSourceAccessor messageSourceAccessor;
  private static final Logger LOGGER = LogManager.getLogger(ExceptionHandlers.class);

  @Autowired
  ExceptionHandlers(final MessageSourceAccessor messageSourceAccessor) {
    super();
    this.messageSourceAccessor = messageSourceAccessor;
  }

  @ExceptionHandler(EntryNotFoundException.class)
  @ResponseStatus(HttpStatus.NOT_FOUND)
  public ResponseError handleNotFoundException(final EntryNotFoundException e) {
    return constructError(e.getMessage());
  }

  @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
  @ResponseStatus(HttpStatus.NOT_FOUND)
  public void handleRequestMethodNotSupportedException(final HttpRequestMethodNotSupportedException e) {
  }

  @ExceptionHandler(PermissionException.class)
  @ResponseStatus(HttpStatus.FORBIDDEN)
  public ResponseError handlePermissionException(final PermissionException error) {
    return constructError(error.getMessage());
  }

  @ExceptionHandler(JsonMappingException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseError handleJsonMappingException(final JsonMappingException e) {
    for (final JsonMappingException.Reference reference : e.getPath()) {
      if ("operations".equals(reference.getFieldName())) {
        return constructError("error.permission.invalid_operation");
      }
    }

    return badRequestResponse();
  }

  @ExceptionHandler(InvalidQueryParameterException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseError handleInvalidParameterException(final InvalidQueryParameterException e) {
    return constructError(e.getMessage(), e.getInvalidQueryParameter());
  }

  @ExceptionHandler(MissingServletRequestParameterException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseError handleMissingParameterException(final MissingServletRequestParameterException e) {
    return constructError("error.missing_query_parameter", e.getParameterName());
  }

  @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseError handleHttpMediaTypeNotSupportedException(final HttpMediaTypeNotSupportedException e) {

    String errorMessage = "";

    final MediaType contentType = e.getContentType();
    if (contentType != null) {
      errorMessage = contentType.toString();
    }

    return constructError("error.invalid_content_type", errorMessage);
  }

  @ExceptionHandler(JsonParseException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseError handleJsonMappingException(final JsonParseException e) {
    return badRequestResponse();
  }

  @ExceptionHandler(ParameterizedValidationException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseError handleParameterizedValidationException(
    final ParameterizedValidationException exception
  ) {
    return constructError(exception.getMessage(), exception.getParameters());
  }

  @ExceptionHandler(UnrecognizedPropertyException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseError handleUnrecognizedPropertyException(final UnrecognizedPropertyException exception) {
    return constructError("error.invalid_json_key", exception.getPropertyName());
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseError handleMethodArgumentNotValidException(final MethodArgumentNotValidException exception) {

    final String message = exception.getBindingResult().getAllErrors().get(0).getDefaultMessage();

    if (message != null) {
      return constructError(message);
    }

    return constructError(exception.getMessage());
  }

  @ExceptionHandler(InvalidRemoteAddressException.class)
  @ResponseStatus(HttpStatus.UNAUTHORIZED)
  public ResponseError handleInvalidRemoteAddressException() {
    return constructError("error.invalid_remote_address");
  }

  @ExceptionHandler(ReadOnlyException.class)
  @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
  public ResponseError handleReadOnlyException() {
    return constructError("error.read_only_mode");
  }

  @ExceptionHandler(UnreadableCertificateException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseError handleUnreadableCertificateException() {
    return constructError("error.unreadable_certificate");
  }

  @ExceptionHandler(MissingCertificateException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseError handleMissingCertificateException() {
    return constructError("error.missing_certificate");
  }

  @ExceptionHandler(MalformedCertificateException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseError handleMalformedCertificateException() {
    return constructError("error.invalid_certificate_value");
  }

  @ExceptionHandler(InvalidJsonException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseError handleInputNotReadableException(final Exception exception) {

    final Throwable cause = exception.getCause() == null ? exception : exception.getCause();

    if (cause instanceof UnrecognizedPropertyException) {
      return constructError("error.invalid_json_key", ((UnrecognizedPropertyException) cause).getPropertyName());
    } else if (cause instanceof InvalidTypeIdException
      || cause instanceof JsonMappingException && cause.getMessage().contains("missing property 'type'")
    ) {
      return constructError("error.invalid_type_with_set_prompt");
    }
    return badRequestResponse();
  }

  @ExceptionHandler(InvalidPermissionOperationException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseError handleIncorrectAclOperation(final InvalidPermissionOperationException e) {
    return constructError(e.getMessage());
  }

  @ExceptionHandler(InvalidPermissionException.class)
  @ResponseStatus(HttpStatus.NOT_FOUND)
  public ResponseError handleInvalidPermission(final InvalidPermissionException e) {
    return constructError(e.getMessage());
  }

  @ExceptionHandler(InvalidModeException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseError handleInvalidMode(final InvalidModeException e) {
    return constructError(e.getMessage());
  }

  @ExceptionHandler(PermissionAlreadyExistsException.class)
  @ResponseStatus(HttpStatus.CONFLICT)
  public ResponseError handleIncorrectAclOperation(final PermissionAlreadyExistsException e) {
    return constructError(e.getMessage());
  }

  @ExceptionHandler(PermissionDoesNotExistException.class)
  @ResponseStatus(HttpStatus.NOT_FOUND)
  public ResponseError handlePermissionDoesNotExist(final PermissionDoesNotExistException e) {
    return constructError(e.getMessage());
  }

  @ExceptionHandler(PermissionInvalidPathAndActorException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseError handlePermissionHasInvalidPathAndActor(final PermissionInvalidPathAndActorException e) {
    return constructError(e.getMessage());
  }

  @ExceptionHandler(KeyNotFoundException.class)
  @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
  public ResponseError handleKeyNotFoundException(final KeyNotFoundException e) {
    return constructError(e.getMessage());
  }

  @ExceptionHandler(InvalidObjectException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseError handleInvalidTypeAccess(final InvalidObjectException exception) {
    return constructError(exception.getMessage());
  }

  @ExceptionHandler(MaximumSizeException.class)
  @ResponseStatus(HttpStatus.PAYLOAD_TOO_LARGE)
  public ResponseError handleMaximumSizeException(final MaximumSizeException exception) {
    return constructError("error.exceeds_maximum_size");
  }

  @ExceptionHandler(MalformedPrivateKeyException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseError handleMalformedPrivateKey(final MalformedPrivateKeyException exception) {
    final ResponseError responseError = constructError("error.malformed_private_key");
    final String exceptionMessage = exception.getMessage();
    if (exceptionMessage != null) {
      final String error = responseError.getError();
      return new ResponseError(String.join(" ", error, exceptionMessage));
    } else {
      return responseError;
    }
  }

  @SuppressWarnings("PMD.UselessParentheses")
  @ExceptionHandler({
    HttpMessageNotReadableException.class,
    InvalidFormatException.class,
  })
  public ResponseError handleIncorrectOperation(final Exception e, final HttpServletResponse response) {
    final Throwable cause = e.getCause() == null ? e : e.getCause();
    response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());

    if (cause instanceof UnrecognizedPropertyException) {
      return constructError("error.invalid_json_key", ((UnrecognizedPropertyException) cause).getPropertyName());

    } else if (
      cause instanceof InvalidTypeIdException ||
        (cause instanceof JsonMappingException && cause.getMessage().contains("missing property 'type'"))
    ) {
      return constructError("error.invalid_type_with_set_prompt");

    } else if (cause instanceof JsonMappingException) {
      for (final JsonMappingException.Reference reference : ((JsonMappingException) cause).getPath()) {
        if ("operations".equals(reference.getFieldName())) {
          return constructError("error.permission.invalid_operation");
        }
      }

    } else if (cause instanceof InvalidFormatException) {
      for (final InvalidFormatException.Reference reference : ((InvalidFormatException) cause)
        .getPath()) {
        if ("operations".equals(reference.getFieldName())) {
          return constructError("error.permission.invalid_operation");
        }
      }

    }
    response.setStatus(HttpStatus.BAD_REQUEST.value());
    return badRequestResponse();
  }

  private ResponseError badRequestResponse() {
    return constructError("error.bad_request");
  }

  private ResponseError constructError(final String error) {
    final String message = messageSourceAccessor.getMessage(error);
    LOGGER.error(message);
    return new ResponseError(message);
  }

  private ResponseError constructError(final String error, final String... args) {
    final String message = messageSourceAccessor.getMessage(error, args);
    LOGGER.error(message);
    return new ResponseError(message);
  }

  private ResponseError constructError(final String error, final Object[] args) {
    final String message = messageSourceAccessor.getMessage(error, args);
    LOGGER.error(message);
    return new ResponseError(message);
  }
}
