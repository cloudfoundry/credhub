package io.pivotal.security.controller.v1;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.mapper.StringGeneratorRequestTranslator;
import io.pivotal.security.model.*;
import io.pivotal.security.repository.SecretStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.util.StringUtils;
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
  SecretStore secretStore;

  @Autowired
  SecretGenerator secretGenerator;

  @Autowired
  StringGeneratorRequestTranslator stringGeneratorRequestTranslator;

  @Autowired
  Configuration jsonPathConfiguration;

  private MessageSourceAccessor messageSourceAccessor;

  @Autowired
  private MessageSource messageSource;

  @PostConstruct
  public void init() {
    messageSourceAccessor = new MessageSourceAccessor(messageSource);
  }

  @RequestMapping(path = "/{secretPath}", method = RequestMethod.POST)
  ResponseEntity generate(@PathVariable String secretPath, InputStream requestBody) {
    DocumentContext parsed = JsonPath.using(jsonPathConfiguration).parse(requestBody);
    String type = parsed.read("$.type");
    if (!"value".equals(type)) {
      return createErrorResponse("error.secret_type_invalid", HttpStatus.BAD_REQUEST);
    }

    try {
      StringGeneratorRequest generatorRequest = stringGeneratorRequestTranslator.validGeneratorRequest(parsed);

      String secretValue = secretGenerator.generateSecret(generatorRequest.getParameters());
      StringSecret stringSecret = new StringSecret(secretValue);

      secretStore.set(secretPath, stringSecret);

      return new ResponseEntity<>(stringSecret, HttpStatus.OK);
    } catch (ValidationException ve) {
      return createErrorResponse(ve.getMessage(), HttpStatus.BAD_REQUEST);
    }
  }

  @RequestMapping(path = "/{secretPath}", method = RequestMethod.PUT)
  ResponseEntity set(@PathVariable String secretPath, InputStream requestBody) {
    DocumentContext parsed = JsonPath.using(jsonPathConfiguration).parse(requestBody);
    String type = parsed.read("$.type");
    if (!"value".equals(type) && !"certificate".equals(type)) {
      return createErrorResponse("error.secret_type_invalid", HttpStatus.BAD_REQUEST);
    }

    if ("value".equals(type)) {
      String value = parsed.read("$.value");
      if (StringUtils.isEmpty(value)) {
        throw new ValidationException(); // spring shows generic invalid message
      }
      StringSecret stringSecret = new StringSecret(value);
      secretStore.set(secretPath, stringSecret);
      return new ResponseEntity<>(stringSecret, HttpStatus.OK);
    } else {
      String ca = parsed.read("$.certificate.ca");
      String pub = parsed.read("$.certificate.public");
      String priv = parsed.read("$.certificate.private");
      CertificateSecret secret = new CertificateSecret(ca, pub, priv);
      secretStore.set(secretPath, secret);
      return new ResponseEntity<>(secret, HttpStatus.OK);
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
    StringSecret stringSecret = secretStore.getStringSecret(secretPath);

    if (stringSecret == null) {
      return createErrorResponse("error.secret_not_found", HttpStatus.NOT_FOUND);
    } else {
      return new ResponseEntity<>(stringSecret, HttpStatus.OK);
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
