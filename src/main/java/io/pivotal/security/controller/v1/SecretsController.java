package io.pivotal.security.controller.v1;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.mapper.*;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordParameters;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.view.Secret;
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
import java.util.Objects;
import java.util.function.Function;

@RestController
@RequestMapping(path = "/api/v1/data", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class SecretsController {

  @Autowired
  SecretRepository secretRepository;

  @Autowired
  ValueGeneratorRequestTranslator valueGeneratorRequestTranslator;

  @Autowired
  PasswordGeneratorRequestTranslator passwordGeneratorRequestTranslator;

  @Autowired
  CertificateGeneratorRequestTranslator certificateGeneratorRequestTranslator;

  @Autowired
  CertificateSetRequestTranslator certificateSetRequestTranslator;

  @Autowired
  ValueSetRequestTranslator valueSetRequestTranslator;

  @Autowired
  PasswordSetRequestTranslator passwordSetRequestTranslator;

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
      return storeSecret(requestBody, secretPath, valueGeneratorRequestTranslator, passwordGeneratorRequestTranslator, certificateGeneratorRequestTranslator);
    });
  }

  @RequestMapping(path = "/{secretPath}", method = RequestMethod.PUT)
  ResponseEntity set(@PathVariable String secretPath, InputStream requestBody, HttpServletRequest request, Authentication authentication) throws Exception {
    return auditLogService.performWithAuditing("credential_update", new AuditRecordParameters(request, authentication), () -> {
      return storeSecret(requestBody, secretPath, valueSetRequestTranslator, passwordSetRequestTranslator, certificateSetRequestTranslator);
    });
  }

  private ResponseEntity storeSecret(InputStream requestBody, String secretPath, RequestTranslator stringRequestTranslator, RequestTranslator passwordRequestTranslator, RequestTranslator certificateRequestTranslator) {
    DocumentContext parsed = JsonPath.using(jsonPathConfiguration).parse(requestBody);
    String type = parsed.read("$.type");
    RequestTranslator requestTranslator = getTranslator(type, stringRequestTranslator, passwordRequestTranslator, certificateRequestTranslator);
    NamedSecret namedSecret = secretRepository.findOneByName(secretPath);

    try {
      if (namedSecret == null) {
        namedSecret = (NamedSecret) requestTranslator.makeEntity(secretPath);
      }

      Secret secret = namedSecret.getViewInstance();

      validateTypeMatch(secret.getType(), type);

      requestTranslator.populateEntityFromJson(namedSecret, parsed);
      NamedSecret saved = secretRepository.save(namedSecret);
      Secret stringSecret = secret.generateView(saved);
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
        Secret secret = namedSecret.getViewInstance();
        return new ResponseEntity<>(secret.generateView(namedSecret), HttpStatus.OK);
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

  private void validateTypeMatch(String storedType, String providedType) {
    if (!Objects.equals(storedType, providedType)) {
      throw new ValidationException("error.type_mismatch");
    }
  }

  private RequestTranslator getTranslator(String type, RequestTranslator stringRequestTranslator, RequestTranslator passwordRequstTranslator, RequestTranslator certificateRequestTranslator) {
    if("value".equals(type)) {
      return stringRequestTranslator;
    } else if ("password".equals(type)) {
      return passwordRequstTranslator;
    } else if("certificate".equals(type)) {
      return certificateRequestTranslator;
    }

    return new InvalidTranslator();
  }

  private class InvalidTranslator implements RequestTranslator {
    @Override
    public NamedSecret makeEntity(String name) {
      throw new ValidationException("error.type_invalid");
    }

    @Override
    public Object populateEntityFromJson(Object namedSecret, DocumentContext documentContext) {
      throw new ValidationException("error.type_invalid");
    }
  }
}
