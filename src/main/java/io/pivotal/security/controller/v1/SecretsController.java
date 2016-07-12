package io.pivotal.security.controller.v1;

import com.google.common.collect.ImmutableMap;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.mapper.*;
import io.pivotal.security.repository.InMemorySecretRepository;
import io.pivotal.security.view.CertificateSecret;
import io.pivotal.security.view.Secret;
import io.pivotal.security.view.StringSecret;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.*;

import javax.annotation.PostConstruct;
import javax.validation.ValidationException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;

@RestController
@RequestMapping(path = "/api/v1/data", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class SecretsController {

  @Autowired
  InMemorySecretRepository secretRepository;

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

  private MessageSourceAccessor messageSourceAccessor;

  @Autowired
  private MessageSource messageSource;

  @Autowired
  private StringSetRequestTranslator stringSetRequestTranslator;

  @PostConstruct
  public void init() {
    messageSourceAccessor = new MessageSourceAccessor(messageSource);
  }

  @RequestMapping(path = "/{secretPath}", method = RequestMethod.POST)
  ResponseEntity generate(@PathVariable String secretPath, InputStream requestBody) {
    RequestTranslatorWithGeneration stringRequestTranslator = new RequestTranslatorWithGeneration(stringSecretGenerator, stringGeneratorRequestTranslator);
    RequestTranslatorWithGeneration certificateRequestTranslator = new RequestTranslatorWithGeneration(certificateSecretGenerator, certificateGeneratorRequestTranslator);

    return storeSecret(requestBody, secretPath, stringRequestTranslator, certificateRequestTranslator);
  }

  @RequestMapping(path = "/{secretPath}", method = RequestMethod.PUT)
  ResponseEntity set(@PathVariable String secretPath, InputStream requestBody) {
    return storeSecret(requestBody, secretPath, stringSetRequestTranslator, certificateSetRequestTranslator);
  }

  private ResponseEntity storeSecret(InputStream requestBody, String secretPath, SecretSetterRequestTranslator stringRequestTranslator, SecretSetterRequestTranslator certificateRequestTranslator) {
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
  ResponseEntity delete(@PathVariable String secretPath) {
    NamedSecret namedSecret = secretRepository.findOneByName(secretPath);

    if (namedSecret != null) {
      secretRepository.delete(namedSecret);
      return new ResponseEntity(HttpStatus.OK);
    } else {
      return createErrorResponse("error.secret_not_found", HttpStatus.NOT_FOUND);
    }
  }

  @RequestMapping(path = "/{secretPath}", method = RequestMethod.GET)
  ResponseEntity get(@PathVariable String secretPath) {
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
