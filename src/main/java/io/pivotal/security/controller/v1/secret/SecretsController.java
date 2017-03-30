package io.pivotal.security.controller.v1.secret;

import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.fasterxml.jackson.databind.exc.InvalidTypeIdException;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import com.google.common.io.ByteStreams;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.InvalidJsonException;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import io.pivotal.security.config.JsonContextFactory;
import io.pivotal.security.controller.v1.SecretKindMappingFactory;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.entity.AuditingOperationCode;
import io.pivotal.security.exceptions.KeyNotFoundException;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.BaseSecretGenerateRequest;
import io.pivotal.security.request.BaseSecretSetRequest;
import io.pivotal.security.request.DefaultSecretGenerateRequest;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.service.SecretRequestService;
import io.pivotal.security.util.CheckedFunction;
import io.pivotal.security.view.DataResponse;
import io.pivotal.security.view.FindCredentialResults;
import io.pivotal.security.view.FindPathResults;
import io.pivotal.security.view.ResponseError;
import io.pivotal.security.view.SecretKind;
import io.pivotal.security.view.SecretKindFromString;
import io.pivotal.security.view.SecretView;
import org.apache.commons.lang.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.util.IOUtils;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.orm.jpa.JpaSystemException;
import org.springframework.security.core.Authentication;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static com.google.common.collect.Lists.newArrayList;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_FIND;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_UPDATE;

@RestController
@RequestMapping(
    path = SecretsController.API_V1_DATA,
    produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class SecretsController {

  public static final String API_V1_DATA = "/api/v1/data";

  private static final Logger LOGGER = LogManager.getLogger(SecretsController.class);
  private final SecretDataService secretDataService;
  private final NamedSecretGenerateHandler namedSecretGenerateHandler;
  private final JsonContextFactory jsonContextFactory;
  private final AuditLogService auditLogService;
  private final MessageSourceAccessor messageSourceAccessor;
  private final ObjectMapper objectMapper;
  private final SecretRequestService secretRequestService;

  public SecretsController(SecretDataService secretDataService,
                           NamedSecretGenerateHandler namedSecretGenerateHandler,
                           JsonContextFactory jsonContextFactory,
                           MessageSource messageSource,
                           AuditLogService auditLogService,

                           ObjectMapper objectMapper,
                           SecretRequestService secretRequestService) {
    this.secretDataService = secretDataService;
    this.namedSecretGenerateHandler = namedSecretGenerateHandler;
    this.jsonContextFactory = jsonContextFactory;
    this.auditLogService = auditLogService;
    this.messageSourceAccessor = new MessageSourceAccessor(messageSource);
    this.objectMapper = objectMapper;
    this.secretRequestService = secretRequestService;
  }

  @RequestMapping(path = "", method = RequestMethod.POST)
  public ResponseEntity generate(InputStream inputStream,
                                 HttpServletRequest request,
                                 Authentication authentication) throws Exception {
    try {
      return auditedHandlePostRequest(inputStream, request, authentication);
    } catch (JpaSystemException | DataIntegrityViolationException e) {
      return auditedHandlePostRequest(inputStream, request, authentication);
    }
  }

  private ResponseEntity auditedHandlePostRequest(
      InputStream inputStream,
      HttpServletRequest request,
      Authentication authentication
  ) throws Exception {
    return auditLogService.performWithAuditing((auditRecordBuilder -> {
      return deserializeAndHandlePostRequest(
          inputStream,
          request,
          authentication,
          auditRecordBuilder);
    }));
  }

  private ResponseEntity<?> deserializeAndHandlePostRequest(
      InputStream inputStream,
      HttpServletRequest request,
      Authentication authentication,
      AuditRecordBuilder auditRecordBuilder) throws Exception {
    InputStream requestInputStream = new ByteArrayInputStream(ByteStreams.toByteArray(inputStream));
    String requestString = IOUtils.toString(new InputStreamReader(requestInputStream));
    boolean isRegenerateRequest = readRegenerateFlagFrom(requestString);

    auditRecordBuilder.populateFromRequest(request);
    auditRecordBuilder.setAuthentication(authentication);
    if (isRegenerateRequest) {
      // If it's a regenerate request deserialization is simple; the generation case requires
      // polymorphic deserialization See BaseSecretGenerateRequest to see how that's done. It
      // would be nice if Jackson could pick a subclass based on an arbitrary function, since
      // we want to consider both type and .regenerate. We could do custom deserialization but
      // then we'd have to do the entire job by hand.
      return handleRegenerateRequest(auditRecordBuilder, requestInputStream);
    } else {
      return handleGenerateRequest(auditRecordBuilder, requestInputStream, requestString);
    }
  }

  private ResponseEntity handleGenerateRequest(
      AuditRecordBuilder auditRecordBuilder,
      InputStream requestInputStream, String requestString
  ) throws Exception {
    BaseSecretGenerateRequest requestBody =
        objectMapper.readValue(requestString, BaseSecretGenerateRequest.class);
    requestBody.validate();

    auditRecordBuilder.setCredentialName(requestBody.getName());
    final boolean isCurrentlyTrappedInTheMonad =
        requestBody instanceof DefaultSecretGenerateRequest;
    if (isCurrentlyTrappedInTheMonad) {
      requestInputStream.reset();
      DocumentContext parsedRequestBody = jsonContextFactory.getObject().parse(requestInputStream);
      return storeSecret(auditRecordBuilder, namedSecretGenerateHandler, parsedRequestBody);
    } else {
      try {
        return secretRequestService.perform(auditRecordBuilder, requestBody);
      } catch (JpaSystemException | DataIntegrityViolationException e) {
        LOGGER.error(
            "Exception \"" + e.getMessage() + "\" with class \"" + e.getClass().getCanonicalName()
                + "\" while storing secret, possibly caused by race condition, retrying...");
        return secretRequestService.perform(auditRecordBuilder, requestBody);
      }
    }
  }

  private ResponseEntity handleRegenerateRequest(
      AuditRecordBuilder auditRecordBuilder,
      InputStream requestInputStream
  ) throws Exception {
    requestInputStream.reset();
    DocumentContext parsedRequestBody = jsonContextFactory.getObject().parse(requestInputStream);
    return storeSecret(auditRecordBuilder, namedSecretGenerateHandler, parsedRequestBody);
  }

  @RequestMapping(path = "", method = RequestMethod.PUT)
  public ResponseEntity set(@RequestBody BaseSecretSetRequest requestBody,
                            HttpServletRequest request,
                            Authentication authentication) throws Exception {
    requestBody.validate();

    try {
      return auditedHandlePutRequest(requestBody, request, authentication);
    } catch (JpaSystemException | DataIntegrityViolationException e) {
      return auditedHandlePutRequest(requestBody, request, authentication);
    }
  }

  private ResponseEntity auditedHandlePutRequest(
      @RequestBody BaseSecretSetRequest requestBody,
      HttpServletRequest request,
      Authentication authentication
  ) throws Exception {
    return auditLogService.performWithAuditing(auditRecordBuilder -> {
      return handlePutRequest(requestBody, request, authentication, auditRecordBuilder);
    });
  }

  private ResponseEntity<?> handlePutRequest(
      @RequestBody BaseSecretSetRequest requestBody,
      HttpServletRequest request,
      Authentication authentication,
      AuditRecordBuilder auditRecordBuilder
  ) throws Exception {
    auditRecordBuilder.setCredentialName(requestBody.getName());
    auditRecordBuilder.populateFromRequest(request);
    auditRecordBuilder.setAuthentication(authentication);
    try {
      return secretRequestService.perform(auditRecordBuilder, requestBody);
    } catch (JpaSystemException | DataIntegrityViolationException e) {
      LOGGER.error(
          "Exception \"" + e.getMessage() + "\" with class \"" + e.getClass().getCanonicalName()
              + "\" while storing secret, possibly caused by race condition, retrying...");
      return secretRequestService.perform(auditRecordBuilder, requestBody);
    }
  }

  @RequestMapping(path = "", method = RequestMethod.DELETE)
  public ResponseEntity delete(@RequestParam(value = "name", required = false) String secretName,
                               HttpServletRequest request,
                               Authentication authentication) throws Exception {
    return auditLogService.performWithAuditing(auditRecorder -> {
      auditRecorder.setCredentialName(secretName);
      auditRecorder.populateFromRequest(request);
      auditRecorder.setAuthentication(authentication);

      if (StringUtils.isEmpty(secretName)) {
        return new ResponseEntity<>(createErrorResponse("error.missing_name"),
            HttpStatus.BAD_REQUEST);
      }
      if (secretDataService.findMostRecent(secretName) == null) {
        return new ResponseEntity<>(createErrorResponse("error.credential_not_found"),
            HttpStatus.NOT_FOUND);
      }

      secretDataService.delete(secretName);
      return new ResponseEntity(HttpStatus.NO_CONTENT);
    });
  }

  @RequestMapping(path = "/{id}", method = RequestMethod.GET)
  public ResponseEntity getSecretById(
      @PathVariable String id,
      HttpServletRequest request,
      Authentication authentication) throws Exception {

    return retrieveSecretWithAuditing(
        id,
        findAsList(secretDataService::findByUuid),
        request,
        authentication,
        true
    );
  }

  @RequestMapping(path = "", method = RequestMethod.GET)
  public ResponseEntity getSecret(
      @RequestParam(value = "name", required = false) String secretName,
      @RequestParam(value = "current", required = false, defaultValue = "false") boolean current,
      HttpServletRequest request,
      Authentication authentication) throws Exception {

    return retrieveSecretWithAuditing(
        secretName,
        selectLookupFunction(current),
        request,
        authentication,
        false
    );
  }

  private Function<String, List<NamedSecret>> selectLookupFunction(boolean current) {
    if (current) {
      return findAsList(secretDataService::findMostRecent);
    } else {
      return secretDataService::findAllByName;
    }
  }

  private Function<String, List<NamedSecret>> findAsList(Function<String, NamedSecret> finder) {
    return (toFind) -> {
      NamedSecret namedSecret = finder.apply(toFind);
      return namedSecret != null ? newArrayList(namedSecret) : newArrayList();
    };
  }

  private ResponseEntity retrieveSecretWithAuditing(String identifier,
                                                    Function<String, List<NamedSecret>> finder,
                                                    HttpServletRequest request,
                                                    Authentication authentication,
                                                    boolean returnFirstEntry) throws Exception {
    return auditLogService.performWithAuditing(auditRecordBuilder -> {
      auditRecordBuilder.populateFromRequest(request);
      auditRecordBuilder.setAuthentication(authentication);

      if (StringUtils.isEmpty(identifier)) {
        return new ResponseEntity<>(createErrorResponse("error.missing_name"),
            HttpStatus.BAD_REQUEST);
      }
      List<NamedSecret> namedSecrets = finder.apply(identifier);
      if (namedSecrets.isEmpty()) {
        return new ResponseEntity<>(createErrorResponse("error.credential_not_found"),
            HttpStatus.NOT_FOUND);
      } else {
        ResponseEntity success;
        auditRecordBuilder.setCredentialName(namedSecrets.get(0).getName());
        try {
          if (returnFirstEntry) {
            success = new ResponseEntity<>(SecretView.fromEntity(namedSecrets.get(0)),
                HttpStatus.OK);
          } else {
            success = new ResponseEntity<>(DataResponse.fromEntity(namedSecrets), HttpStatus.OK);
          }
        } catch (KeyNotFoundException e) {
          return new ResponseEntity<>(createErrorResponse("error.missing_encryption_key"),
              HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (NoSuchAlgorithmException e) {
          throw new RuntimeException(e);
        }
        return success;
      }
    });
  }

  @RequestMapping(path = "", params = "path", method = RequestMethod.GET)
  public ResponseEntity findByPath(
      @RequestParam Map<String, String> params,
      HttpServletRequest request,
      Authentication authentication
  ) throws Exception {
    return findStartingWithAuditing(params.get("path"), request, authentication);
  }

  @RequestMapping(path = "", params = "paths=true", method = RequestMethod.GET)
  public ResponseEntity findPaths(HttpServletRequest request, Authentication authentication)
      throws Exception {
    return findPathsWithAuditing(request, authentication);
  }

  @RequestMapping(path = "", params = "name-like", method = RequestMethod.GET)
  public ResponseEntity findByNameLike(
      @RequestParam Map<String, String> params,
      HttpServletRequest request,
      Authentication authentication
  ) throws Exception {
    return findWithAuditing(params.get("name-like"), secretDataService::findContainingName, request,
        authentication);
  }

  @ExceptionHandler({HttpMessageNotReadableException.class, InvalidJsonException.class})
  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  public ResponseError handleInputNotReadableException(Exception exception) throws Exception {
    String errorMessage = messageSourceAccessor.getMessage("error.bad_request");
    final Throwable cause = exception.getCause();
    if (cause instanceof UnrecognizedPropertyException) {
      return createParameterizedErrorResponse(
          new ParameterizedValidationException("error.invalid_json_key",
              ((UnrecognizedPropertyException) cause).getPropertyName())
      );
    } else if (cause instanceof InvalidTypeIdException
        || (cause instanceof JsonMappingException && cause.getMessage()
        .contains("missing property 'type'"))) {
      errorMessage = messageSourceAccessor.getMessage("error.invalid_type_with_set_prompt");
    } else if (cause instanceof InvalidFormatException) {
      for (InvalidFormatException.Reference reference : ((InvalidFormatException) cause)
          .getPath()) {
        if ("operations".equals(reference.getFieldName())) {
          errorMessage = messageSourceAccessor.getMessage("error.acl.invalid_operation");
          return new ResponseError(errorMessage);
        }
      }
    }
    return new ResponseError(errorMessage);
  }

  @ExceptionHandler(ParameterizedValidationException.class)
  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  public ResponseError handleParameterizedValidationException(
      ParameterizedValidationException exception) throws Exception {
    return createParameterizedErrorResponse(exception);
  }

  @ExceptionHandler(UnrecognizedPropertyException.class)
  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  public ResponseError handleUnrecognizedPropertyException(UnrecognizedPropertyException exception)
      throws Exception {
    return createParameterizedErrorResponse(
        new ParameterizedValidationException("error.invalid_json_key", exception.getPropertyName())
    );

  }

  @ExceptionHandler({MethodArgumentNotValidException.class})
  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  public ResponseError handleInvalidField(MethodArgumentNotValidException exception)
      throws IOException {
    ObjectError error = exception.getBindingResult().getAllErrors().get(0);
    String errorMessage = messageSourceAccessor.getMessage(error.getDefaultMessage());
    return new ResponseError(errorMessage);
  }

  private boolean readRegenerateFlagFrom(String requestString) {
    boolean isRegenerateRequest;
    try {
      isRegenerateRequest = JsonPath.read(requestString, "$.regenerate");
    } catch (PathNotFoundException e) {
      // could have just returned null, that would have been pretty useful
      isRegenerateRequest = false;
    }
    return isRegenerateRequest;
  }

  private ResponseEntity findWithAuditing(String nameSubstring,
                                          Function<String, List<SecretView>> finder,
                                          HttpServletRequest request,
                                          Authentication authentication) throws Exception {
    return auditLogService.performWithAuditing(auditParams -> {
      auditParams.populateFromRequest(request);
      auditParams.setAuthentication(authentication);
      auditParams.setOperationCode(CREDENTIAL_FIND);
      List<SecretView> secretViews = finder.apply(nameSubstring);
      return new ResponseEntity<>(FindCredentialResults.fromSecrets(secretViews), HttpStatus.OK);
    });
  }

  private ResponseEntity findPathsWithAuditing(
      HttpServletRequest request,
      Authentication authentication
  ) throws Exception {
    return auditLogService.performWithAuditing(auditParams -> {
      auditParams.populateFromRequest(request);
      auditParams.setAuthentication(authentication);
      auditParams.setOperationCode(CREDENTIAL_FIND);
      List<String> paths = secretDataService.findAllPaths();
      return new ResponseEntity<>(FindPathResults.fromEntity(paths), HttpStatus.OK);
    });
  }

  private ResponseEntity<?> storeSecret(
      AuditRecordBuilder auditRecordBuilder,
      SecretKindMappingFactory handler,
      DocumentContext parsedRequestBody
  ) throws Exception {
    final String secretName = getSecretName(parsedRequestBody);
    if (StringUtils.isEmpty(secretName)) {
      return new ResponseEntity<>(createErrorResponse("error.missing_name"),
          HttpStatus.BAD_REQUEST);
    }
    NamedSecret existingNamedSecret = secretDataService.findMostRecent(secretName);

    boolean willBeCreated = existingNamedSecret == null;
    boolean overwrite = BooleanUtils.isTrue(parsedRequestBody.read("$.overwrite", Boolean.class));
    boolean regenerate = BooleanUtils.isTrue(parsedRequestBody.read("$.regenerate", Boolean.class));

    boolean willWrite = willBeCreated || overwrite || regenerate;
    AuditingOperationCode operationCode = willWrite ? CREDENTIAL_UPDATE : CREDENTIAL_ACCESS;
    auditRecordBuilder.setOperationCode(operationCode);
    if (regenerate && existingNamedSecret == null) {
      return new ResponseEntity<>(
          createErrorResponse("error.credential_not_found"),
          HttpStatus.NOT_FOUND);
    }

    String secretPath = secretName;
    try {
      String requestedSecretType = parsedRequestBody.read("$.type");
      final SecretKind secretKind = (existingNamedSecret != null
          ? existingNamedSecret.getKind()
          : SecretKindFromString.fromString(requestedSecretType));
      if (existingNamedSecret != null && requestedSecretType != null && !existingNamedSecret
          .getSecretType().equals(requestedSecretType)) {
        throw new ParameterizedValidationException("error.type_mismatch");
      }
      secretPath = existingNamedSecret == null ? secretPath : existingNamedSecret.getName();

      NamedSecret storedNamedSecret;
      if (willWrite) {
        SecretKind.CheckedMapping<NamedSecret, NoSuchAlgorithmException> make =
            handler.make(secretPath, parsedRequestBody);
        CheckedFunction<NamedSecret, NoSuchAlgorithmException> lift = secretKind.lift(make);
        storedNamedSecret = lift.apply(existingNamedSecret);
        storedNamedSecret = secretDataService.save(storedNamedSecret);
      } else {
        // To catch invalid parameters, validate request even though we throw away the result.
        // We need to apply it to null or Hibernate may decide to save the record.
        // As above, the unit tests won't catch (all) issues :( ,
        // but there is an integration test to cover it.
        storedNamedSecret = existingNamedSecret;
        secretKind.lift(handler.make(secretPath, parsedRequestBody)).apply(null);
      }

      SecretView secretView = SecretView.fromEntity(storedNamedSecret);
      return new ResponseEntity<>(secretView, HttpStatus.OK);
    } catch (ParameterizedValidationException ve) {
      return new ResponseEntity<>(createParameterizedErrorResponse(ve), HttpStatus.BAD_REQUEST);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    } catch (KeyNotFoundException e) {
      return new ResponseEntity<>(createErrorResponse("error.missing_encryption_key"),
          HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  private String getSecretName(DocumentContext parsed) {
    return parsed.read("$.name", String.class);
  }

  private ResponseError createErrorResponse(String key) {
    return createParameterizedErrorResponse(new ParameterizedValidationException(key));
  }

  private ResponseError createParameterizedErrorResponse(
      ParameterizedValidationException exception) {
    String errorMessage = messageSourceAccessor
        .getMessage(exception.getMessage(), exception.getParameters());
    return new ResponseError(errorMessage);
  }

  private ResponseEntity findStartingWithAuditing(String path, HttpServletRequest request,
                                                  Authentication authentication) throws Exception {
    return findWithAuditing(path, secretDataService::findStartingWithPath, request, authentication);
  }
}
