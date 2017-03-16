package io.pivotal.security.controller.v1.secret;

import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.entity.AuditingOperationCode;
import io.pivotal.security.exceptions.KeyNotFoundException;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.BaseSecretGenerateRequest;
import io.pivotal.security.request.BaseSecretPostRequest;
import io.pivotal.security.request.BaseSecretPutRequest;
import io.pivotal.security.request.DefaultSecretGenerateRequest;
import io.pivotal.security.request.SecretRegenerateRequest;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordBuilder;
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
import org.springframework.validation.annotation.Validated;
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
@RequestMapping(path = SecretsController.API_V1_DATA, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class SecretsController {

  public static final String API_V1_DATA = "/api/v1/data";

  private static final Logger logger = LogManager.getLogger(SecretsController.class);

  private SecretDataService secretDataService;
  private NamedSecretGenerateHandler namedSecretGenerateHandler;
  private JsonContextFactory jsonContextFactory;
  private AuditLogService auditLogService;
  private MessageSourceAccessor messageSourceAccessor;
  private Encryptor encryptor;
  private ObjectMapper objectMapper;

  public SecretsController(SecretDataService secretDataService,
                           NamedSecretGenerateHandler namedSecretGenerateHandler,
                           JsonContextFactory jsonContextFactory,
                           MessageSource messageSource,
                           AuditLogService auditLogService,
                           Encryptor encryptor,
                           ObjectMapper objectMapper) {
    this.secretDataService = secretDataService;
    this.namedSecretGenerateHandler = namedSecretGenerateHandler;
    this.jsonContextFactory = jsonContextFactory;
    this.auditLogService = auditLogService;
    this.messageSourceAccessor = new MessageSourceAccessor(messageSource);
    this.encryptor = encryptor;
    this.objectMapper = objectMapper;
  }

  @RequestMapping(path = "", method = RequestMethod.POST)
  public ResponseEntity generate(InputStream inputStream,
                                 HttpServletRequest request,
                                 Authentication authentication) throws Exception {
    InputStream requestInputStream = new ByteArrayInputStream(ByteStreams.toByteArray(inputStream));
    BaseSecretPostRequest requestBody = parseRequestJson(requestInputStream);
    requestBody.validate();

    if(true || requestBody instanceof DefaultSecretGenerateRequest){
      requestInputStream.reset();
      DocumentContext parsedRequestBody = jsonContextFactory.getObject().parse(requestInputStream);
      return retryingAuditedStoreSecret(request, authentication, namedSecretGenerateHandler, parsedRequestBody);
    } else {
//      requestBody.createNewVersion();
      return null;
    }
  }

  @RequestMapping(path = "", method = RequestMethod.PUT)
  public ResponseEntity set(
      @RequestBody @Validated BaseSecretPutRequest requestBody,
      HttpServletRequest request,
      Authentication authentication
  ) throws Exception {
    try {
      return performSet(request, authentication, requestBody);
    } catch (JpaSystemException | DataIntegrityViolationException e) {
      logger.error("Exception \"" + e.getMessage() + "\" with class \"" + e.getClass().getCanonicalName() + "\" while storing secret, possibly caused by race condition, retrying...");
      return performSet(request, authentication, requestBody);
    }
  }

  @RequestMapping(path = "", method = RequestMethod.DELETE)
  public ResponseEntity delete(@RequestParam(value = "name", required = false) String secretName,
                               HttpServletRequest request,
                               Authentication authentication) throws Exception {
    AuditRecordBuilder auditRecorder = new AuditRecordBuilder(null, request, authentication);
    return auditLogService.performWithAuditing(auditRecorder, () -> {
      auditRecorder.setCredentialName(secretName);

      if (StringUtils.isEmpty(secretName)) {
        return new ResponseEntity<>(createErrorResponse("error.missing_name"), HttpStatus.BAD_REQUEST);
      }
      if (secretDataService.findMostRecent(secretName) == null) {
        return new ResponseEntity<>(createErrorResponse("error.credential_not_found"), HttpStatus.NOT_FOUND);
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
    final AuditRecordBuilder auditRecordBuilder = new AuditRecordBuilder(null, request, authentication);
      return auditLogService.performWithAuditing(auditRecordBuilder, () -> {
          if (StringUtils.isEmpty(identifier)) {
              return new ResponseEntity<>(createErrorResponse("error.missing_name"), HttpStatus.BAD_REQUEST);
          }
          List<NamedSecret> namedSecrets = finder.apply(identifier);
          if (namedSecrets.isEmpty()) {
            return new ResponseEntity<>(createErrorResponse("error.credential_not_found"), HttpStatus.NOT_FOUND);
          } else {
              ResponseEntity success;
              auditRecordBuilder.setCredentialName(namedSecrets.get(0).getName());
              try {
                  if (returnFirstEntry) {
                      success = new ResponseEntity<>(SecretView.fromEntity(namedSecrets.get(0)), HttpStatus.OK);
                  } else {
                      success = new ResponseEntity<>(DataResponse.fromEntity(namedSecrets), HttpStatus.OK);
                  }
              } catch (KeyNotFoundException e) {
                return new ResponseEntity<>(createErrorResponse("error.missing_encryption_key"), HttpStatus.INTERNAL_SERVER_ERROR);
              } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
              }
              return success;
          }
      });
  }

  @RequestMapping(path = "", params = "path", method = RequestMethod.GET)
  public ResponseEntity findByPath(@RequestParam Map<String, String> params, HttpServletRequest request, Authentication authentication) throws Exception {
    return findStartingWithAuditing(params.get("path"), request, authentication);
  }

  @RequestMapping(path = "", params = "paths=true", method = RequestMethod.GET)
  public ResponseEntity findPaths(HttpServletRequest request, Authentication authentication) throws Exception {
    return findPathsWithAuditing(request, authentication);
  }

  @RequestMapping(path = "", params = "name-like", method = RequestMethod.GET)
  public ResponseEntity findByNameLike(@RequestParam Map<String, String> params, HttpServletRequest request, Authentication authentication) throws Exception {
    return findWithAuditing(params.get("name-like"), secretDataService::findContainingName, request, authentication);
  }

  @ExceptionHandler({HttpMessageNotReadableException.class, InvalidJsonException.class})
  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  public ResponseError handleInputNotReadableException(Exception exception) throws Exception {
    String errorMessage;
    final Throwable cause = exception.getCause();
    if (cause instanceof UnrecognizedPropertyException) {
      return createParameterizedErrorResponse(
        new ParameterizedValidationException("error.invalid_json_key", ((UnrecognizedPropertyException) cause).getPropertyName())
      );
    } else if (cause instanceof InvalidTypeIdException) {
      errorMessage = messageSourceAccessor.getMessage("error.type_invalid");
    } else if (cause instanceof JsonMappingException && cause.getMessage().contains("missing property 'type'")) {
      errorMessage = messageSourceAccessor.getMessage("error.type_invalid");
    } else {
      errorMessage = messageSourceAccessor.getMessage("error.bad_request");
    }

    return new ResponseError(errorMessage);
  }

  @ExceptionHandler(ParameterizedValidationException.class)
  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  public ResponseError handleParameterizedValidationException(ParameterizedValidationException exception) throws Exception {
    return createParameterizedErrorResponse(exception);
  }

  @ExceptionHandler({MethodArgumentNotValidException.class})
  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  public ResponseError handleInvalidField(MethodArgumentNotValidException exception) throws IOException {
    ObjectError error = exception.getBindingResult().getAllErrors().get(0);
    String errorMessage = messageSourceAccessor.getMessage(error.getDefaultMessage());
    return new ResponseError(errorMessage);
  }

  private BaseSecretPostRequest parseRequestJson(InputStream requestInputStream) throws IOException {
    String requestString = IOUtils.toString(new InputStreamReader(requestInputStream));
    boolean isRegenerateRequest;
    try {
      isRegenerateRequest = JsonPath.read(requestString, "$.regenerate");
    } catch(PathNotFoundException e) {
      // could have just returned null, that would have been pretty useful
      isRegenerateRequest = false;
    }
    BaseSecretPostRequest requestBody;
    if (isRegenerateRequest) {
      requestBody = objectMapper.readValue(requestString, SecretRegenerateRequest.class);
    } else {
      requestBody = objectMapper.readValue(requestString, BaseSecretGenerateRequest.class);
    }
    return requestBody;
  }

  private ResponseEntity findWithAuditing(String nameSubstring,
                                          Function<String, List<SecretView>> finder,
                                          HttpServletRequest request,
                                          Authentication authentication) throws Exception {
    AuditRecordBuilder auditParams = new AuditRecordBuilder(null, request, authentication).setOperationCode(CREDENTIAL_FIND);
    return auditLogService.performWithAuditing(auditParams, () -> {
      List<SecretView> secretViews = finder.apply(nameSubstring);
      return new ResponseEntity<>(FindCredentialResults.fromSecrets(secretViews), HttpStatus.OK);
    });
  }

  private ResponseEntity findPathsWithAuditing(HttpServletRequest request, Authentication authentication) throws Exception {
    AuditRecordBuilder auditParams = new AuditRecordBuilder(null, request, authentication).setOperationCode(CREDENTIAL_FIND);
    return auditLogService.performWithAuditing(auditParams, () -> {
      List<String> paths = secretDataService.findAllPaths();
      return new ResponseEntity<>(FindPathResults.fromEntity(paths), HttpStatus.OK);
    });
  }

  private ResponseEntity retryingAuditedStoreSecret(HttpServletRequest request, Authentication authentication, SecretKindMappingFactory requestHandler, DocumentContext parsedRequestBody) throws Exception {
    try {
      return auditedStoreSecret(request, authentication, requestHandler, parsedRequestBody);
    } catch (JpaSystemException | DataIntegrityViolationException e) {
      System.out.println("Exception \"" + e.getMessage() + "\" with class \"" + e.getClass().getCanonicalName() + "\" while storing secret, possibly caused by race condition, retrying...");
      return auditedStoreSecret(request, authentication, requestHandler, parsedRequestBody);
    }
  }

  private ResponseEntity<?> auditedStoreSecret(HttpServletRequest request,
                                               Authentication authentication,
                                               SecretKindMappingFactory handler, DocumentContext parsedRequestBody) throws Exception {
    final String secretName = getSecretName(parsedRequestBody);
    if (StringUtils.isEmpty(secretName)) {
      return new ResponseEntity<>(createErrorResponse("error.missing_name"), HttpStatus.BAD_REQUEST);
    }
    NamedSecret existingNamedSecret = secretDataService.findMostRecent(secretName);

    boolean willBeCreated = existingNamedSecret == null;
    boolean overwrite = BooleanUtils.isTrue(parsedRequestBody.read("$.overwrite", Boolean.class));
    boolean regenerate = BooleanUtils.isTrue(parsedRequestBody.read("$.regenerate", Boolean.class));

    boolean willWrite = willBeCreated || overwrite || regenerate;
    AuditingOperationCode operationCode = willWrite ? CREDENTIAL_UPDATE : CREDENTIAL_ACCESS;
    final AuditRecordBuilder auditRecordBuilder = new AuditRecordBuilder(secretName, request, authentication);
    auditRecordBuilder.setOperationCode(operationCode);
    return auditLogService.performWithAuditing(auditRecordBuilder, () -> {
      if (regenerate && existingNamedSecret == null) {
        return new ResponseEntity<>(createErrorResponse("error.credential_not_found"), HttpStatus.NOT_FOUND);
      }

      return storeSecret(secretName, handler, parsedRequestBody, existingNamedSecret, willWrite);
    });
  }

  private String getSecretName(DocumentContext parsed) {
    return parsed.read("$.name", String.class);
  }

  private ResponseEntity<?> storeSecret(String secretPath,
                                        SecretKindMappingFactory namedSecretHandler,
                                        DocumentContext parsedRequest,
                                        NamedSecret existingNamedSecret,
                                        boolean willWrite) {
    try {
      String requestedSecretType = parsedRequest.read("$.type");
      final SecretKind secretKind = (existingNamedSecret != null ?
          existingNamedSecret.getKind() :
          SecretKindFromString.fromString(requestedSecretType));
      if (existingNamedSecret != null && requestedSecretType != null && !existingNamedSecret.getSecretType().equals(requestedSecretType))
        throw new ParameterizedValidationException("error.type_mismatch");
      secretPath = existingNamedSecret == null ? secretPath : existingNamedSecret.getName();

      NamedSecret storedNamedSecret;
      if (willWrite) {
        SecretKind.CheckedMapping<NamedSecret, NoSuchAlgorithmException> make = namedSecretHandler.make(secretPath, parsedRequest);
        CheckedFunction<NamedSecret, NoSuchAlgorithmException> lift = secretKind.lift(make);
        storedNamedSecret = lift.apply(existingNamedSecret);
        storedNamedSecret = secretDataService.save(storedNamedSecret);
      } else {
        // To catch invalid parameters, validate request even though we throw away the result.
        // We need to apply it to null or Hibernate may decide to save the record.
        // As above, the unit tests won't catch (all) issues :( , but there is an integration test to cover it.
        storedNamedSecret = existingNamedSecret;
        secretKind.lift(namedSecretHandler.make(secretPath, parsedRequest)).apply(null);
      }

      SecretView secretView = SecretView.fromEntity(storedNamedSecret);
      return new ResponseEntity<>(secretView, HttpStatus.OK);
    } catch (ParameterizedValidationException ve) {
      return new ResponseEntity<>(createParameterizedErrorResponse(ve), HttpStatus.BAD_REQUEST);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    } catch (KeyNotFoundException e) {
        return new ResponseEntity<>(createErrorResponse("error.missing_encryption_key"), HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  private ResponseError createErrorResponse(String key) {
    return createParameterizedErrorResponse(new ParameterizedValidationException(key));
  }

  private ResponseError createParameterizedErrorResponse(ParameterizedValidationException exception) {
    String errorMessage = messageSourceAccessor.getMessage(exception.getMessage(), exception.getParameters());
    return new ResponseError(errorMessage);
  }

  private ResponseEntity findStartingWithAuditing(String path, HttpServletRequest request, Authentication authentication) throws Exception {
    return findWithAuditing(path, secretDataService::findStartingWithPath, request, authentication);
  }

  private ResponseEntity performSet(
      HttpServletRequest request,
      Authentication authentication,
      BaseSecretPutRequest requestBody) throws Exception {

    final String secretName = requestBody.getName();

    NamedSecret existingNamedSecret = secretDataService.findMostRecent(secretName);

    boolean willBeCreated = existingNamedSecret == null;
    boolean overwrite = requestBody.isOverwrite();
    boolean willWrite = willBeCreated || overwrite;

    AuditingOperationCode operationCode = willWrite ? CREDENTIAL_UPDATE : CREDENTIAL_ACCESS;
    final AuditRecordBuilder auditRecordBuilder = new AuditRecordBuilder(secretName, request, authentication);
    auditRecordBuilder.setOperationCode(operationCode);

    return auditLogService.performWithAuditing(auditRecordBuilder, () -> {
      try {
        if (existingNamedSecret != null && !existingNamedSecret.getSecretType().equals(requestBody.getType())) {
          throw new ParameterizedValidationException("error.type_mismatch");
        }

        NamedSecret storedEntity = existingNamedSecret;
        if (willWrite) {
          NamedSecret newEntity = requestBody.createNewVersion(
              existingNamedSecret,
              secretName,
              encryptor
          );

          storedEntity = secretDataService.save(newEntity);
        }

        SecretView secretView = SecretView.fromEntity(storedEntity);
        return new ResponseEntity<>(secretView, HttpStatus.OK);
      } catch (ParameterizedValidationException ve) {
        return new ResponseEntity<>(createParameterizedErrorResponse(ve), HttpStatus.BAD_REQUEST);
      } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException(e);
      } catch (KeyNotFoundException e) {
        return new ResponseEntity<>(createErrorResponse("error.missing_encryption_key"), HttpStatus.INTERNAL_SERVER_ERROR);
      }
    });
  }
}
