package io.pivotal.security.controller.v1;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordParameters;
import io.pivotal.security.util.CurrentTimeProvider;
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
import org.springframework.web.bind.annotation.*;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.validation.ValidationException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.function.Function;

@RestController
@RequestMapping(path = "/api/v1/data", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class SecretsController {

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

  @RequestMapping(path = "/{secretPath}", method = RequestMethod.POST)
  ResponseEntity generate(@PathVariable String secretPath, InputStream requestBody, HttpServletRequest request, Authentication authentication) throws Exception {
    return auditLogService.performWithAuditing("credential_update", new AuditRecordParameters(request, authentication), () -> {
      return storeSecret(requestBody, secretPath, namedSecretGenerateHandler);
    });
  }

  @RequestMapping(path = "/{secretPath}", method = RequestMethod.PUT)
  ResponseEntity set(@PathVariable String secretPath, InputStream requestBody, HttpServletRequest request, Authentication authentication) throws Exception {
    return auditLogService.performWithAuditing("credential_update", new AuditRecordParameters(request, authentication), () -> {
      return storeSecret(requestBody, secretPath, namedSecretSetHandler);
    });
  }

  private ResponseEntity<?> storeSecret(InputStream requestBody, String secretPath, SecretKindMappingFactory namedSecretHandler) {
    final DocumentContext parsed = JsonPath.using(jsonPathConfiguration).parse(requestBody);

    try {
      final SecretKind secretKind = SecretKindFromString.fromString(parsed.read("$.type"));

      NamedSecret namedSecret = secretRepository.findOneByName(secretPath);

      boolean willBeCreated = namedSecret == null;
      boolean overwrite = BooleanUtils.isTrue(parsed.read("$.parameters.overwrite", Boolean.class));

      if (willBeCreated || overwrite) {
        namedSecret = secretKind.map(namedSecretHandler.make(secretPath, parsed)).apply(namedSecret);
        namedSecret = secretRepository.save(namedSecret);
      }

      Secret stringSecret = Secret.fromEntity(namedSecret);
      return new ResponseEntity<>(stringSecret, HttpStatus.OK);
    } catch (ValidationException ve) {
      return createErrorResponse(ve.getMessage(), HttpStatus.BAD_REQUEST);
    }
  }

  @RequestMapping(path = "/{secretPath}", method = RequestMethod.DELETE)
  ResponseEntity delete(@PathVariable String secretPath, HttpServletRequest request, Authentication authentication) throws Exception {
    return auditLogService.performWithAuditing("credential_delete", new AuditRecordParameters(request, authentication), () -> {
      NamedSecret namedSecret = secretRepository.findOneByName(secretPath);
      if (namedSecret != null) {
        secretRepository.delete(namedSecret);
        return new ResponseEntity(HttpStatus.OK);
      } else {
        return createErrorResponse("error.secret_not_found", HttpStatus.NOT_FOUND);
      }
    });
  }

  @RequestMapping(path = "/{secretPath}", method = RequestMethod.GET)
  public ResponseEntity getByName(@PathVariable String secretPath, HttpServletRequest request, Authentication authentication) throws Exception {
    return retrieveWithAuditing(secretPath, secretRepository::findOneByName, request, authentication);
  }

  @RequestMapping(method = RequestMethod.GET)
  public ResponseEntity getByUuid(@RequestParam("id") String uuid, HttpServletRequest request, Authentication authentication) throws Exception {
    return retrieveWithAuditing(uuid, secretRepository::findOneByUuid, request, authentication);
  }

  private ResponseEntity retrieveWithAuditing(String identifier, Function<String, NamedSecret> finder, HttpServletRequest request, Authentication authentication) throws Exception {
    return auditLogService.performWithAuditing("credential_access", new AuditRecordParameters(request, authentication), () -> {
      NamedSecret namedSecret = finder.apply(identifier);
      if (namedSecret == null) {
        return createErrorResponse("error.secret_not_found", HttpStatus.NOT_FOUND);
      } else {
        return new ResponseEntity<>(Secret.fromEntity(namedSecret), HttpStatus.OK);
      }
    });
  }

  @ExceptionHandler({HttpMessageNotReadableException.class, ValidationException.class, com.jayway.jsonpath.InvalidJsonException.class})
  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  public ResponseError handleInputNotReadableException() throws IOException {
    return new ResponseError(ResponseErrorType.BAD_REQUEST);
  }

  private ResponseEntity createErrorResponse(String key, HttpStatus status) {
    String errorMessage = messageSourceAccessor.getMessage(key);
    return new ResponseEntity<>(Collections.singletonMap("error", errorMessage), status);
  }
}