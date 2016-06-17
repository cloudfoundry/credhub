package io.pivotal.security.controller.v1;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.mapper.*;
import io.pivotal.security.model.*;
import io.pivotal.security.repository.SecretStore;
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
import java.util.function.Function;
import java.util.function.Supplier;

import javax.annotation.PostConstruct;
import javax.validation.ValidationException;


@RestController
@RequestMapping(path = "/api/v1/data", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class SecretsController {

  @Autowired
  SecretStore secretStore;

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
    return dispatchOnSecretType(requestBody, (parsed) -> {
      return generateAndStoreSecret(secretPath, parsed, stringGeneratorRequestTranslator, stringSecretGenerator);
    }, (parsed) -> {
      return generateAndStoreSecret(secretPath, parsed, certificateGeneratorRequestTranslator, certificateSecretGenerator);
    });
  }

  private Secret generateAndStoreSecret(@PathVariable String secretPath, DocumentContext parsed, SecretGeneratorRequestTranslator generatorRequestTranslator, SecretGenerator secretGenerator) {
    GeneratorRequest generatorRequest = generatorRequestTranslator.validGeneratorRequest(parsed);

    Secret secretValue = secretGenerator.generateSecret(generatorRequest.getParameters());

    secretStore.set(secretPath, secretValue);

    return secretValue;
  }

  @RequestMapping(path = "/{secretPath}", method = RequestMethod.PUT)
  ResponseEntity set(@PathVariable String secretPath, InputStream requestBody) {
    return dispatchOnSecretType(requestBody, (parsed) -> {
      return setAndStoreSecret(secretPath, parsed, stringSetRequestTranslator);
    }, (parsed) -> {
      return setAndStoreSecret(secretPath, parsed, certificateSetRequestTranslator);
    });
  }

  private Secret setAndStoreSecret(@PathVariable String secretPath, DocumentContext parsed, SecretSetterRequestTranslator setterRequestTranslator) {
    Secret secretValue = setterRequestTranslator.createSecretFromJson(parsed);

    secretStore.set(secretPath, secretValue);

    return secretValue;
  }

  private ResponseEntity dispatchOnSecretType(InputStream requestBody,
                                              Function<DocumentContext, Secret> ifValueType,
                                              Function<DocumentContext, Secret> ifCertificateType) {
    DocumentContext parsed = JsonPath.using(jsonPathConfiguration).parse(requestBody);
    String type = parsed.read("$.type");
    try {
      if (type == null) {
        throw new ValidationException("error.secret_type_invalid");
      }
      try {
        Supplier<Secret> ifValue = () -> ifValueType.apply(parsed);
        Supplier<Secret> ifCertificate = () -> ifCertificateType.apply(parsed);
        final Secret secret = SecretType.valueOf(type).enumerate(ifValue, ifCertificate);
        return new ResponseEntity<>(secret, HttpStatus.OK);
      } catch (IllegalArgumentException e) {
        throw new ValidationException("error.secret_type_invalid");
      }
    } catch (ValidationException ve) {
      return createErrorResponse(ve.getMessage(), HttpStatus.BAD_REQUEST);
    }
  }

  @RequestMapping(path = "/{secretPath}", method = RequestMethod.DELETE)
  ResponseEntity delete(@PathVariable String secretPath) {
    boolean wasDeleted = secretStore.delete(secretPath);

    if (wasDeleted) {
      return new ResponseEntity(HttpStatus.OK);
    } else {
      return createErrorResponse("error.secret_not_found", HttpStatus.NOT_FOUND);
    }
  }

  @RequestMapping(path = "/{secretPath}", method = RequestMethod.GET)
  ResponseEntity get(@PathVariable String secretPath) {
    Object secret = secretStore.getSecret(secretPath);

    if (secret == null) {
      return createErrorResponse("error.secret_not_found", HttpStatus.NOT_FOUND);
    } else {
      return new ResponseEntity<>(secret, HttpStatus.OK);
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
