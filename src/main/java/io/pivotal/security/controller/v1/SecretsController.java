package io.pivotal.security.controller.v1;

import com.google.common.collect.ImmutableMap;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.mapper.CertificateGeneratorRequestTranslator;
import io.pivotal.security.mapper.CertificateSetRequestTranslator;
import io.pivotal.security.mapper.RequestTranslatorWithGeneration;
import io.pivotal.security.mapper.SecretSetterRequestTranslator;
import io.pivotal.security.mapper.StringGeneratorRequestTranslator;
import io.pivotal.security.mapper.StringSetRequestTranslator;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.view.CertificateSecret;
import io.pivotal.security.view.Secret;
import io.pivotal.security.view.StringSecret;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.validation.ValidationException;

@RestController
@RequestMapping(path = "/api/v1/data", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class SecretsController {

  @Autowired
  SecretRepository secretRepository;

  @Autowired
  SecretGenerator<StringSecretParameters, StringSecret> stringSecretGenerator;

  @Autowired
  SecretGenerator<CertificateSecretParameters, CertificateSecret> certificateSecretGenerator;

  @Autowired
  StringGeneratorRequestTranslator stringGeneratorRequestTranslator;

  @Autowired
  CertificateGeneratorRequestTranslator certificateGeneratorRequestTranslator;

  @Autowired
  CertificateSetRequestTranslator certificateSetRequestTranslator;

  @Autowired
  Configuration jsonPathConfiguration;

  @Autowired
  ResourceServerTokenServices tokenServices;

  private MessageSourceAccessor messageSourceAccessor;

  @Autowired
  private MessageSource messageSource;

  @Autowired
  private StringSetRequestTranslator stringSetRequestTranslator;

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
  ResponseEntity generate(@PathVariable String secretPath, InputStream requestBody, HttpServletRequest request) {
    RequestTranslatorWithGeneration stringRequestTranslator = new RequestTranslatorWithGeneration(stringSecretGenerator, stringGeneratorRequestTranslator);
    RequestTranslatorWithGeneration certificateRequestTranslator = new RequestTranslatorWithGeneration(certificateSecretGenerator, certificateGeneratorRequestTranslator);

    return auditLogService.performWithAuditing("credential_update", request.getServerName(), request.getRequestURI(), () -> {
      return storeSecret(requestBody, secretPath, stringRequestTranslator, certificateRequestTranslator, request);
    });
  }

  @RequestMapping(path = "/{secretPath}", method = RequestMethod.PUT)
  ResponseEntity set(@PathVariable String secretPath, InputStream requestBody, HttpServletRequest request) {
    return auditLogService.performWithAuditing("credential_update", request.getServerName(), request.getRequestURI(), () -> {
      return storeSecret(requestBody, secretPath, stringSetRequestTranslator, certificateSetRequestTranslator, request);
    });
  }

  private ResponseEntity storeSecret(InputStream requestBody, String secretPath, SecretSetterRequestTranslator stringRequestTranslator, SecretSetterRequestTranslator certificateRequestTranslator, HttpServletRequest request) {
    DocumentContext parsed = JsonPath.using(jsonPathConfiguration).parse(requestBody);
    String type = parsed.read("$.type");
    SecretSetterRequestTranslator requestTranslator = getTranslator(type, stringRequestTranslator, certificateRequestTranslator); //
    NamedSecret foundNamedSecret = secretRepository.findOneByName(secretPath);

    NamedSecret toStore;
    try {
      Secret secret = requestTranslator.createSecretFromJson(parsed);
      if (foundNamedSecret == null) {
        toStore = requestTranslator.makeEntity(secretPath);
      } else {
        toStore = foundNamedSecret;
        validateTypeMatch(foundNamedSecret, secret);
      }
      secret.populateEntity(toStore);
      NamedSecret saved = secretRepository.save(toStore);
      secret.setUpdatedAt(saved.getUpdatedAt());
      return new ResponseEntity<>(secret, HttpStatus.OK);
    } catch (ValidationException ve) {
      return createErrorResponse(ve.getMessage(), HttpStatus.BAD_REQUEST);
    }
  }

  @RequestMapping(path = "/{secretPath}", method = RequestMethod.DELETE)
  ResponseEntity delete(@PathVariable String secretPath, HttpServletRequest request) {
    NamedSecret namedSecret = secretRepository.findOneByName(secretPath);

    if (namedSecret != null) {
      secretRepository.delete(namedSecret);
      return new ResponseEntity(HttpStatus.OK);
    } else {
      return createErrorResponse("error.secret_not_found", HttpStatus.NOT_FOUND);
    }
  }

  @RequestMapping(path = "/{secretPath}", method = RequestMethod.GET)
  public ResponseEntity get(@PathVariable String secretPath) {
    NamedSecret namedSecret = secretRepository.findOneByName(secretPath);

    if (namedSecret == null) {
      return createErrorResponse("error.secret_not_found", HttpStatus.NOT_FOUND);
    } else {
      return new ResponseEntity<>(namedSecret.generateView(), HttpStatus.OK);
    }
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

  private void validateTypeMatch(NamedSecret foundNamedSecret, Secret secret) {
    Secret foundSecret = (Secret) (foundNamedSecret.generateView());
    if (!secret.getType().equals(foundSecret.getType())) {
      throw new ValidationException("error.type_mismatch");
    }
  }

  private SecretSetterRequestTranslator getTranslator(String type, SecretSetterRequestTranslator stringRequestTranslator, SecretSetterRequestTranslator certificateRequestTranslator) {
    SecretSetterRequestTranslator map = ImmutableMap.of("value", stringRequestTranslator, "certificate", certificateRequestTranslator).get(type);
    if (map == null) {
      map = new InvalidTranslator();
    }

    return map;
  }

  private class InvalidTranslator implements SecretSetterRequestTranslator {
    @Override
    public Secret createSecretFromJson(DocumentContext documentContext) {
      throw new ValidationException("error.type_invalid");
    }

    @Override
    public NamedSecret makeEntity(String name) {
      return null;
    }
  }

}
