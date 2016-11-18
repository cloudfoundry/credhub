package io.pivotal.security.controller.v1.secret;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.controller.v1.ResponseError;
import io.pivotal.security.controller.v1.ResponseErrorType;
import io.pivotal.security.controller.v1.SecretKindMappingFactory;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.entity.AuditingOperationCode;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordParameters;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.view.DataResponse;
import io.pivotal.security.view.FindCredentialResults;
import io.pivotal.security.view.FindPathResults;
import io.pivotal.security.view.ParameterizedValidationException;
import io.pivotal.security.view.Secret;
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
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_FIND;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_UPDATE;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;

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
  ParseContext jsonPath;

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

  @RequestMapping(path = "/**", method = RequestMethod.POST)
  public ResponseEntity generate(InputStream requestBody, HttpServletRequest request, Authentication authentication) throws Exception {
    return auditedStoreSecret(requestBody, request, authentication, namedSecretGenerateHandler);
  }

  @RequestMapping(path = "/**", method = RequestMethod.PUT)
  public ResponseEntity set(InputStream requestBody, HttpServletRequest request, Authentication authentication) throws Exception {
    return auditedStoreSecret(requestBody, request, authentication, namedSecretSetHandler);
  }

  @RequestMapping(path = "/**", method = RequestMethod.DELETE)
  public ResponseEntity delete( @RequestParam(value = "name", required = false) String secretName,
                                HttpServletRequest request,
                                Authentication authentication) throws Exception {
    return auditLogService.performWithAuditing(new AuditRecordParameters(null, request, authentication), () -> {
      List<NamedSecret> namedSecrets;
      String nameToDelete = secretName;
      if (nameToDelete == null) {
        nameToDelete = secretPath(request);
      }

      if (StringUtils.isEmpty(nameToDelete)) {
        throw new ParameterizedValidationException("error.missing_name");
      }

      namedSecrets = secretDataService.delete(nameToDelete);

      if (namedSecrets.size() > 0) {
        return new ResponseEntity(HttpStatus.OK);
      } else {
        return createErrorResponse("error.credential_not_found", HttpStatus.NOT_FOUND);
      }
    });
  }

  @RequestMapping(path = "", method = RequestMethod.GET)
  public ResponseEntity getSecret(
      @RequestParam(value = "name", required = false) String secretName,
      @RequestParam(value = "current", required = false, defaultValue = "false") boolean current,
      @RequestParam(value = "id", required = false) String id,
      HttpServletRequest request,
      Authentication authentication) throws Exception {

    String secretIdentifier = id != null ? id : secretName;

    return retrieveSecretWithAuditing(
        secretIdentifier,
        selectLookupFunction(current, id),
        request,
        authentication,
        selectPresenterFunction(id)
    );
  }

  private Function<List<NamedSecret>, Object> selectPresenterFunction(String id) {
    if (id != null) {
      return (namedSecrets) -> Secret.fromEntity(namedSecrets.get(0));
    } else {
      return (namedSecrets) -> DataResponse.fromEntity(namedSecrets, Secret::fromEntity);
    }
  }

  private Function<String, List<NamedSecret>> selectLookupFunction(boolean current, String id) {
    if (id != null) {
      return secretDataService::findByUuidAsList;
    } else {
      if (current) {
        return secretDataService::findMostRecentAsList;
      } else {
        return secretDataService::findAllByName;
      }
    }
  }

  @RequestMapping(path = "/**", method = RequestMethod.GET)
  public ResponseEntity getSecretByPath(HttpServletRequest request, Authentication authentication) throws Exception {
    return retrieveSecretWithAuditing(secretPath(request), secretDataService::findMostRecentAsList, request, authentication, (namedSecrets) -> Secret
        .fromEntity(namedSecrets.get(0)));
  }

  private ResponseEntity retrieveSecretWithAuditing(String identifier,
                                                    Function<String, List<NamedSecret>> finder,
                                                    HttpServletRequest request,
                                                    Authentication authentication,
                                                    Function<List<NamedSecret>, Object> secretPresenter) throws Exception {
    return auditLogService.performWithAuditing(new AuditRecordParameters(null, request, authentication), () -> {
      List<NamedSecret> namedSecrets = finder.apply(identifier);
      if (namedSecrets.isEmpty()) {
        return createErrorResponse("error.credential_not_found", HttpStatus.NOT_FOUND);
      } else {
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
    AuditRecordParameters auditParams = new AuditRecordParameters(CREDENTIAL_FIND, null, request, authentication);
    return auditLogService.performWithAuditing(auditParams, () -> {
      List<NamedSecret> namedSecrets = finder.apply(nameSubstring);
      return new ResponseEntity<>(FindCredentialResults.fromEntity(namedSecrets), HttpStatus.OK);
    });
  }

  private ResponseEntity findPathsWithAuditing(HttpServletRequest request, Authentication authentication) throws Exception {
    AuditRecordParameters auditParams = new AuditRecordParameters(CREDENTIAL_FIND, null, request, authentication);
    return auditLogService.performWithAuditing(auditParams, () -> {
      List<String> paths = secretDataService.findAllPaths();
      return new ResponseEntity<>(FindPathResults.fromEntity(paths), HttpStatus.OK);
    });
  }

  private ResponseEntity<?> auditedStoreSecret(InputStream requestBody,
                                               HttpServletRequest request,
                                               Authentication authentication,
                                               SecretKindMappingFactory handler) throws Exception {
    final DocumentContext parsed = jsonPath.parse(requestBody);

    String secretPath = secretPath(request);
    final String secretName;
    if (secretPath.isEmpty()) {
      secretName = parsed.read("$.name", String.class);
    } else {
      secretName = secretPath;
    }

    NamedSecret existingNamedSecret = secretDataService.findMostRecent(secretName);

    boolean willBeCreated = existingNamedSecret == null;
    boolean overwrite = BooleanUtils.isTrue(parsed.read("$.overwrite", Boolean.class));
    boolean regenerate = BooleanUtils.isTrue(parsed.read("$.regenerate", Boolean.class));

    boolean willWrite = willBeCreated || overwrite || regenerate;
    AuditingOperationCode operationCode = willWrite ? CREDENTIAL_UPDATE : CREDENTIAL_ACCESS;
    return auditLogService.performWithAuditing(new AuditRecordParameters(operationCode, secretName, request, authentication), () -> {
      if (regenerate && existingNamedSecret == null) {
        return createErrorResponse("error.credential_not_found", HttpStatus.NOT_FOUND);
      }

      return storeSecret(secretName, handler, parsed, existingNamedSecret, willWrite);
    });
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

      Secret secret = Secret.fromEntity(storedNamedSecret);
      return new ResponseEntity<>(secret, HttpStatus.OK);
    } catch (ParameterizedValidationException ve) {
      return createParameterizedErrorResponse(ve, HttpStatus.BAD_REQUEST);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  private String secretPath(HttpServletRequest request) {
    String requestURI = request.getRequestURI();
    String path = requestURI.replace(API_V1_DATA, "");
    if (path.startsWith("/")) {
      path = path.substring(1);
    }
    return path;
  }

  private ResponseEntity createErrorResponse(String key, HttpStatus status) {
    return createParameterizedErrorResponse(new ParameterizedValidationException(key), status);
  }

  private ResponseEntity createParameterizedErrorResponse(ParameterizedValidationException exception, HttpStatus status) {
    String errorMessage = messageSourceAccessor.getMessage(exception.getMessage(), exception.getParameters());
    return new ResponseEntity<>(Collections.singletonMap("error", errorMessage), status);
  }

  private ResponseEntity findStartingWithAuditing(String path, HttpServletRequest request, Authentication authentication) throws Exception {
    return findWithAuditing(path, secretDataService::findStartingWithName, request, authentication);
  }
}
