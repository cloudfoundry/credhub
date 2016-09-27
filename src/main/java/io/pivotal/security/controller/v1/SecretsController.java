package io.pivotal.security.controller.v1;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordParameters;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.view.FindResults;
import io.pivotal.security.view.ParameterizedValidationException;
import io.pivotal.security.view.Secret;
import io.pivotal.security.view.SecretKind;
import io.pivotal.security.view.SecretKindFromString;
import org.apache.commons.lang.BooleanUtils;
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

import static io.pivotal.security.constants.AuditingOperationCodes.CREDENTIAL_ACCESS;
import static io.pivotal.security.constants.AuditingOperationCodes.CREDENTIAL_DELETE;
import static io.pivotal.security.constants.AuditingOperationCodes.CREDENTIAL_FIND;
import static io.pivotal.security.constants.AuditingOperationCodes.CREDENTIAL_UPDATE;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping(path = SecretsController.API_V1_DATA, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class SecretsController {

  public static final String API_V1_DATA = "/api/v1/data";

  @Autowired
  SecretRepository secretRepository;

  @Autowired
  NamedSecretGenerateHandler namedSecretGenerateHandler;

  @Autowired
  NamedSecretSetHandler namedSecretSetHandler;

  @Autowired
  Configuration jsonPathConfiguration;

  @Autowired
  ResourceServerTokenServices tokenServices;

  private MessageSourceAccessor messageSourceAccessor;

  @Autowired
  private MessageSource messageSource;

  @Autowired
  @Qualifier("currentTimeProvider")
  CurrentTimeProvider currentTimeProvider;

  @Autowired
  ConfigurableEnvironment environment;

  @Autowired
  AuditLogService auditLogService;

  @PostConstruct
  public void init() {
    messageSourceAccessor = new MessageSourceAccessor(messageSource);
  }

  @RequestMapping(path = "/**", method = RequestMethod.POST)
  public ResponseEntity generate(InputStream requestBody, HttpServletRequest request, Authentication authentication) throws Exception {
    return audit(CREDENTIAL_UPDATE, request, authentication, () -> {
      return storeSecret(requestBody, secretPath(request), namedSecretGenerateHandler);
    });
  }

  @RequestMapping(path = "/**", method = RequestMethod.PUT)
  public ResponseEntity set(InputStream requestBody, HttpServletRequest request, Authentication authentication) throws Exception {
    return audit(CREDENTIAL_UPDATE, request, authentication, () -> {
      return storeSecret(requestBody, secretPath(request), namedSecretSetHandler);
    });
  }

  @RequestMapping(path = "/**", method = RequestMethod.DELETE)
  public ResponseEntity delete(HttpServletRequest request, Authentication authentication) throws Exception {
    return audit(CREDENTIAL_DELETE, request, authentication, () -> {
      NamedSecret namedSecret = secretRepository.findOneByName(secretPath(request));
      if (namedSecret != null) {
        secretRepository.delete(namedSecret);
        return new ResponseEntity(HttpStatus.OK);
      } else {
        return createErrorResponse("error.secret_not_found", HttpStatus.NOT_FOUND);
      }
    });
  }

  @RequestMapping(path = "/**", method = RequestMethod.GET)
  public ResponseEntity getByName(HttpServletRequest request, Authentication authentication) throws Exception {
    return retrieveSecretWithAuditing(secretPath(request), secretRepository::findOneByName, request, authentication);
  }

  @RequestMapping(path = "", params = "id", method = RequestMethod.GET)
  public ResponseEntity getById(@RequestParam Map<String, String> params, HttpServletRequest request, Authentication authentication) throws Exception {
    return retrieveSecretWithAuditing(params.get("id"), secretRepository::findOneByUuid, request, authentication);
  }

  @RequestMapping(path = "", params = "path", method = RequestMethod.GET)
  public ResponseEntity findByPath(@RequestParam Map<String, String> params, HttpServletRequest request, Authentication authentication) throws Exception {
    return findStartingWithAuditing(params.get("path"), request, authentication);
  }

  @RequestMapping(path = "", params = "name-like", method = RequestMethod.GET)
  public ResponseEntity findByNameLike(@RequestParam Map<String, String> params, HttpServletRequest request, Authentication authentication) throws Exception {
    return findWithAuditing(params.get("name-like"), secretRepository::findByNameContainingOrderByUpdatedAtDesc, request, authentication);
  }

  @ExceptionHandler({HttpMessageNotReadableException.class, ParameterizedValidationException.class, com.jayway.jsonpath.InvalidJsonException.class})
  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  public ResponseError handleInputNotReadableException() throws IOException {
    return new ResponseError(ResponseErrorType.BAD_REQUEST);
  }

  private ResponseEntity retrieveSecretWithAuditing(String identifier, Function<String, NamedSecret> finder, HttpServletRequest request, Authentication authentication) throws Exception {
    return audit(CREDENTIAL_ACCESS, request, authentication, () -> {
      NamedSecret namedSecret = finder.apply(identifier);
      if (namedSecret == null) {
        return createErrorResponse("error.secret_not_found", HttpStatus.NOT_FOUND);
      } else {
        return new ResponseEntity<>(Secret.fromEntity(namedSecret), HttpStatus.OK);
      }
    });
  }

  private ResponseEntity findWithAuditing(String nameSubstring, Function<String, List<NamedSecret>> finder, HttpServletRequest request, Authentication authentication) throws Exception {
    return audit(CREDENTIAL_FIND, request, authentication, () -> {
      List<NamedSecret> namedSecrets = finder.apply(nameSubstring);
      return new ResponseEntity<>(FindResults.fromEntity(namedSecrets), HttpStatus.OK);
    });
  }

  private ResponseEntity<?> storeSecret(InputStream requestBody, String secretPath, SecretKindMappingFactory namedSecretHandler) {
    final DocumentContext parsed = JsonPath.using(jsonPathConfiguration).parse(requestBody);

    try {
      final SecretKind secretKind = SecretKindFromString.fromString(parsed.read("$.type"));

      NamedSecret namedSecret = secretRepository.findOneByName(secretPath);

      boolean willBeCreated = namedSecret == null;
      boolean overwrite = BooleanUtils.isTrue(parsed.read("$.overwrite", Boolean.class));

      if (willBeCreated || overwrite) {
        // ensure updatedAt is committed with 'saveAndFlush'.
        // note that the test does NOT catch this.
        namedSecret = secretKind.map(namedSecretHandler.make(secretPath, parsed)).apply(namedSecret);
        namedSecret = secretRepository.saveAndFlush(namedSecret);
      } else {
        // To catch invalid parameters, validate request even though we throw away the result.
        // We need to apply it to null or Hibernate may decide to save the record.
        // As above, the unit tests won't catch (all) issues :(
        secretKind.map(namedSecretHandler.make(secretPath, parsed)).apply(null);
      }

      Secret stringSecret = Secret.fromEntity(namedSecret);
      return new ResponseEntity<>(stringSecret, HttpStatus.OK);
    } catch (ParameterizedValidationException ve) {
      return createParameterizedErrorResponse(ve, HttpStatus.BAD_REQUEST);
    }
  }

  private ResponseEntity audit(String operationCode, HttpServletRequest request, Authentication authentication, Supplier<ResponseEntity<?>> action) throws Exception {
    return auditLogService.performWithAuditing(operationCode, new AuditRecordParameters(request, authentication), action);
  }

  private String secretPath(HttpServletRequest request) {
    return request.getRequestURI().replace(API_V1_DATA + "/", "");
  }

  private ResponseEntity createErrorResponse(String key, HttpStatus status) {
    return createParameterizedErrorResponse(new ParameterizedValidationException(key), status);
  }

  private ResponseEntity createParameterizedErrorResponse(ParameterizedValidationException exception, HttpStatus status) {
    String errorMessage = messageSourceAccessor.getMessage(exception.getMessage(), exception.getParameters());
    return new ResponseEntity<>(Collections.singletonMap("error", errorMessage), status);
  }

  private ResponseEntity findStartingWithAuditing(String path, HttpServletRequest request, Authentication authentication) throws Exception {
    if (!path.endsWith("/")) {
      path = path + "/";
    }
    return findWithAuditing(path, secretRepository::findByNameStartingWithOrderByUpdatedAtDesc, request, authentication);
  }
}