package io.pivotal.security.controller.v1;

import com.google.common.collect.ImmutableMap;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.mapper.*;
import io.pivotal.security.model.*;
import io.pivotal.security.repository.InMemorySecretRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
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
import javax.validation.ValidationException;

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
    ImmutableMap<String, SecretSetterRequestTranslator> translators = ImmutableMap.of("value", stringRequestTranslator, "certificate", certificateRequestTranslator);
    SecretSetterRequestTranslator requestTranslator = translators.get(type);
    NamedSecret secretFromDatabase = secretRepository.findOneByName(secretPath);

    try {
      if (requestTranslator == null) {
        throw new ValidationException("error.secret_type_invalid");
      }
      Secret secret = requestTranslator.createSecretFromJson(parsed);
      if (secretFromDatabase == null) {
        secretFromDatabase = requestTranslator.makeEntity(secretPath);
      }
      secret.populateEntity(secretFromDatabase);
      secretRepository.save(secretFromDatabase);
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
      return new ResponseEntity<>(namedSecret.convertToModel(), HttpStatus.OK);
    }
  }

  @ExceptionHandler({HttpMessageNotReadableException.class, ValidationException.class})
  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  public ResponseError handleHttpMessageNotReadableException() throws IOException {
    return new ResponseError(ResponseErrorType.BAD_REQUEST);
  }

  private ResponseEntity createErrorResponse(String key, HttpStatus status) {
    String errorMessage = messageSourceAccessor.getMessage(key);
    return new ResponseEntity<>(Collections.singletonMap("error", errorMessage), status);
  }
}
