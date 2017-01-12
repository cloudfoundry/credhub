package io.pivotal.security.controller.v1.secret;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.config.JsonContextFactory;
import io.pivotal.security.controller.v1.ResponseError;
import io.pivotal.security.controller.v1.ResponseErrorType;
import io.pivotal.security.controller.v1.SecretKindMappingFactory;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.entity.AuditingOperationCode;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.view.DataResponse;
import io.pivotal.security.view.FindCredentialResults;
import io.pivotal.security.view.FindPathResults;
import io.pivotal.security.view.ParameterizedValidationException;
import io.pivotal.security.view.SecretView;
import io.pivotal.security.view.SecretKind;
import io.pivotal.security.view.SecretKindFromString;
import org.apache.commons.lang.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
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

  @Autowired
  SecretDataService secretDataService;

  @Autowired
  NamedSecretGenerateHandler namedSecretGenerateHandler;

  @Autowired
  NamedSecretSetHandler namedSecretSetHandler;

  @Autowired
  JsonContextFactory jsonContextFactory;

  @Autowired
  ResourceServerTokenServices tokenServices;

  @Autowired
  private MessageSource messageSource;

  @Autowired
  @Qualifier("currentTimeProvider")
  CurrentTimeProvider currentTimeProvider;

  @Autowired
  ConfigurableEnvironment environment;

  @Autowired
  AuditLogService auditLogService;

  private MessageSourceAccessor messageSourceAccessor;

  @PostConstruct
  public void init() {
    messageSourceAccessor = new MessageSourceAccessor(messageSource);
  }

  @RequestMapping(path = "", method = RequestMethod.POST)
  public ResponseEntity generate(InputStream requestBody, HttpServletRequest request, Authentication authentication) throws Exception {
    return auditedStoreSecret(requestBody, request, authentication, namedSecretGenerateHandler);
  }

  @RequestMapping(path = "", method = RequestMethod.PUT)
  public ResponseEntity set(InputStream requestBody, HttpServletRequest request, Authentication authentication) throws Exception {
    return auditedStoreSecret(requestBody, request, authentication, namedSecretSetHandler);
  }

  @RequestMapping(path = "", method = RequestMethod.DELETE)
  public ResponseEntity delete(@RequestParam(value = "name", required = false) String secretName,
                               HttpServletRequest request,
                               Authentication authentication) throws Exception {
    AuditRecordBuilder auditRecorder = new AuditRecordBuilder(null, request, authentication);
    return auditLogService.performWithAuditing(auditRecorder, () -> {
      List<NamedSecret> namedSecrets;
      final String nameToDelete = sanitizedName(secretName);

      if (StringUtils.isEmpty(nameToDelete)) {
        return createErrorResponse("error.missing_name", HttpStatus.BAD_REQUEST);
      }

      namedSecrets = secretDataService.delete(nameToDelete);

      if (namedSecrets.size() > 0) {
        auditRecorder.setCredentialName(namedSecrets.get(0).getName());
        return new ResponseEntity(HttpStatus.OK);
      } else {
        return createErrorResponse("error.credential_not_found", HttpStatus.NOT_FOUND);
      }
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
        (namedSecrets) -> SecretView.fromEntity(namedSecrets.get(0))
    );
  }

  @RequestMapping(path = "", method = RequestMethod.GET)
  public ResponseEntity getSecret(
      @RequestParam(value = "name", required = false) String secretName,
      @RequestParam(value = "current", required = false, defaultValue = "false") boolean current,
      HttpServletRequest request,
      Authentication authentication) throws Exception {

    String secretIdentifier = sanitizedName(secretName);

    return retrieveSecretWithAuditing(
        secretIdentifier,
        selectLookupFunction(current),
        request,
        authentication,
        (namedSecrets) -> DataResponse.fromEntity(namedSecrets, SecretView::fromEntity)
    );
  }

  public String sanitizedName(@RequestParam(value = "name", required = false) String secretName) {
    if (secretName != null && secretName.startsWith("/")) {
      secretName = secretName.substring(1);
    }

    return secretName;
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
                                                    Function<List<NamedSecret>, Object> secretPresenter) throws Exception {
    final AuditRecordBuilder auditRecordBuilder = new AuditRecordBuilder(null, request, authentication);
    return auditLogService.performWithAuditing(auditRecordBuilder, () -> {
      if (StringUtils.isEmpty(identifier)) {
        return createErrorResponse("error.missing_name", HttpStatus.BAD_REQUEST);
      }
      List<NamedSecret> namedSecrets = finder.apply(identifier);
      if (namedSecrets.isEmpty()) {
        return createErrorResponse("error.credential_not_found", HttpStatus.NOT_FOUND);
      } else {
        auditRecordBuilder.setCredentialName(namedSecrets.get(0).getName());
        return new ResponseEntity<>(secretPresenter.apply(namedSecrets), HttpStatus.OK);
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

  @ExceptionHandler({HttpMessageNotReadableException.class, ParameterizedValidationException.class, com.jayway.jsonpath.InvalidJsonException.class})
  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  public ResponseError handleInputNotReadableException() throws IOException {
    return new ResponseError(ResponseErrorType.BAD_REQUEST);
  }

  private ResponseEntity findWithAuditing(String nameSubstring,
                                          Function<String, List<NamedSecret>> finder,
                                          HttpServletRequest request,
                                          Authentication authentication) throws Exception {
    AuditRecordBuilder auditParams = new AuditRecordBuilder(CREDENTIAL_FIND, null, request, authentication);
    return auditLogService.performWithAuditing(auditParams, () -> {
      List<NamedSecret> namedSecrets = finder.apply(nameSubstring);
      return new ResponseEntity<>(FindCredentialResults.fromEntity(namedSecrets), HttpStatus.OK);
    });
  }

  private ResponseEntity findPathsWithAuditing(HttpServletRequest request, Authentication authentication) throws Exception {
    AuditRecordBuilder auditParams = new AuditRecordBuilder(CREDENTIAL_FIND, null, request, authentication);
    return auditLogService.performWithAuditing(auditParams, () -> {
      List<String> paths = secretDataService.findAllPaths();
      return new ResponseEntity<>(FindPathResults.fromEntity(paths), HttpStatus.OK);
    });
  }

  private ResponseEntity<?> auditedStoreSecret(InputStream requestBody,
                                               HttpServletRequest request,
                                               Authentication authentication,
                                               SecretKindMappingFactory handler) throws Exception {
    final DocumentContext parsedRequestBody = jsonContextFactory.getObject().parse(requestBody);
    final String secretName = getSecretName(parsedRequestBody);
    if (StringUtils.isEmpty(secretName)) {
      return createErrorResponse("error.missing_name", HttpStatus.BAD_REQUEST);
    }
    NamedSecret existingNamedSecret = secretDataService.findMostRecent(secretName);

    boolean willBeCreated = existingNamedSecret == null;
    boolean overwrite = BooleanUtils.isTrue(parsedRequestBody.read("$.overwrite", Boolean.class));
    boolean regenerate = BooleanUtils.isTrue(parsedRequestBody.read("$.regenerate", Boolean.class));

    boolean willWrite = willBeCreated || overwrite || regenerate;
    AuditingOperationCode operationCode = willWrite ? CREDENTIAL_UPDATE : CREDENTIAL_ACCESS;
    return auditLogService.performWithAuditing(new AuditRecordBuilder(operationCode, secretName, request, authentication), () -> {
      if (regenerate && existingNamedSecret == null) {
        return createErrorResponse("error.credential_not_found", HttpStatus.NOT_FOUND);
      }

      return storeSecret(secretName, handler, parsedRequestBody, existingNamedSecret, willWrite);
    });
  }

  private String getSecretName(DocumentContext parsed) {
    return sanitizedName(parsed.read("$.name", String.class));
  }

  private ResponseEntity<?> storeSecret(String secretPath,
                                        SecretKindMappingFactory namedSecretHandler,
                                        DocumentContext parsed,
                                        NamedSecret existingNamedSecret,
                                        boolean willWrite) {
    try {
      String requestedSecretType = parsed.read("$.type");
      final SecretKind secretKind = (existingNamedSecret != null ?
          existingNamedSecret.getKind() :
          SecretKindFromString.fromString(requestedSecretType));
      if (existingNamedSecret != null && requestedSecretType != null && !existingNamedSecret.getSecretType().equals(requestedSecretType))
        throw new ParameterizedValidationException("error.type_mismatch");
      secretPath = existingNamedSecret == null ? secretPath : existingNamedSecret.getName();

      NamedSecret storedNamedSecret;
      if (willWrite) {
        storedNamedSecret = secretKind.lift(namedSecretHandler.make(secretPath, parsed)).apply(existingNamedSecret);
        storedNamedSecret = secretDataService.save(storedNamedSecret);
      } else {
        // To catch invalid parameters, validate request even though we throw away the result.
        // We need to apply it to null or Hibernate may decide to save the record.
        // As above, the unit tests won't catch (all) issues :( , but there is an integration test to cover it.
        storedNamedSecret = existingNamedSecret;
        secretKind.lift(namedSecretHandler.make(secretPath, parsed)).apply(null);
      }

      SecretView secretView = SecretView.fromEntity(storedNamedSecret);
      return new ResponseEntity<>(secretView, HttpStatus.OK);
    } catch (ParameterizedValidationException ve) {
      return createParameterizedErrorResponse(ve, HttpStatus.BAD_REQUEST);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  private ResponseEntity createErrorResponse(String key, HttpStatus status) {
    return createParameterizedErrorResponse(new ParameterizedValidationException(key), status);
  }

  private ResponseEntity createParameterizedErrorResponse(ParameterizedValidationException exception, HttpStatus status) {
    String errorMessage = messageSourceAccessor.getMessage(exception.getMessage(), exception.getParameters());
    return new ResponseEntity<>(Collections.singletonMap("error", errorMessage), status);
  }

  private ResponseEntity findStartingWithAuditing(String path, HttpServletRequest request, Authentication authentication) throws Exception {
    return findWithAuditing(sanitizedName(path), secretDataService::findStartingWithName, request, authentication);
  }
}
