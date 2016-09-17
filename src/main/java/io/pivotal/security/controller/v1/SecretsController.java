package io.pivotal.security.controller.v1;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordParameters;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.StringUtil;
import io.pivotal.security.view.*;
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
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.InputStream;
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
  ResponseEntity generate(InputStream requestBody, HttpServletRequest request, Authentication authentication) throws Exception {
    return auditLogService.performWithAuditing("credential_update", new AuditRecordParameters(request, authentication), () -> {
      return storeSecret(requestBody, secretPath(request), namedSecretGenerateHandler);
    });
  }

  @RequestMapping(path = "/**", method = RequestMethod.PUT)
  ResponseEntity set(InputStream requestBody, HttpServletRequest request, Authentication authentication) throws Exception {
    return auditLogService.performWithAuditing("credential_update", new AuditRecordParameters(request, authentication), () -> {
      return storeSecret(requestBody, secretPath(request), namedSecretSetHandler);
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
        namedSecret = secretKind.map(namedSecretHandler.make(secretPath, parsed)).apply(namedSecret);
        namedSecret = secretRepository.save(namedSecret);
      } else {
        // to catch invalid parameters, validate request even though we throw away the result
        secretKind.map(namedSecretHandler.make(secretPath, parsed)).apply(namedSecret);
      }

      Secret stringSecret = Secret.fromEntity(namedSecret);
      return new ResponseEntity<>(stringSecret, HttpStatus.OK);
    } catch (ParameterizedValidationException ve) {
      return createParameterizedErrorResponse(ve, HttpStatus.BAD_REQUEST);
    }
  }

  @RequestMapping(path = "/**", method = RequestMethod.DELETE)
  ResponseEntity delete(HttpServletRequest request, Authentication authentication) throws Exception {
    return auditLogService.performWithAuditing("credential_delete", new AuditRecordParameters(request, authentication), () -> {
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

  @RequestMapping(method = RequestMethod.GET)
  public ResponseEntity getByRequestParam(@RequestParam Map<String, String> params, HttpServletRequest request, Authentication authentication) throws Exception {
    if (params.containsKey("name-like")) {
      return findByNameLike(params.get("name-like"), request, authentication);
    }
    return retrieveSecretWithAuditing(params.get("id"), secretRepository::findOneByUuid, request, authentication);
  }

  private ResponseEntity findByNameLike(String nameSubstring, HttpServletRequest request, Authentication authentication) throws Exception {
    return auditLogService.performWithAuditing("credential_find", new AuditRecordParameters(request, authentication), () -> {
      List<NamedSecret> namedSecrets = secretRepository.findByNameContainingOrderByUpdatedAtDesc(nameSubstring);
      if (namedSecrets == null) {
        return createErrorResponse("error.secret_not_found", HttpStatus.NOT_FOUND);
      } else {
        return new ResponseEntity<>(FindResults.fromEntity(namedSecrets), HttpStatus.OK);
      }
    });
  }

  private ResponseEntity retrieveSecretWithAuditing(String identifier, Function<String, NamedSecret> finder, HttpServletRequest request, Authentication authentication) throws Exception {
    return auditLogService.performWithAuditing("credential_access", new AuditRecordParameters(request, authentication), () -> {
      NamedSecret namedSecret = finder.apply(identifier);
      if (namedSecret == null) {
        return createErrorResponse("error.secret_not_found", HttpStatus.NOT_FOUND);
      } else {
        return new ResponseEntity<>(Secret.fromEntity(namedSecret), HttpStatus.OK);
      }
    });
  }

  @ExceptionHandler({HttpMessageNotReadableException.class, ParameterizedValidationException.class, com.jayway.jsonpath.InvalidJsonException.class})
  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  public ResponseError handleInputNotReadableException() throws IOException {
    return new ResponseError(ResponseErrorType.BAD_REQUEST);
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
}