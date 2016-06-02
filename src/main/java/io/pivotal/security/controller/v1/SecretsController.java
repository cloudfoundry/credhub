package io.pivotal.security.controller.v1;

import io.pivotal.security.model.Secret;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.model.GeneratorRequest;
import io.pivotal.security.model.ResponseError;
import io.pivotal.security.model.ResponseErrorType;
import io.pivotal.security.model.SecretParameters;
import io.pivotal.security.repository.SecretStore;
import io.pivotal.security.validator.GeneratorRequestValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.annotation.PostConstruct;
import javax.validation.Valid;
import javax.validation.ValidationException;
import java.io.IOException;
import java.util.Collections;


@RestController
@RequestMapping(path = "/api/v1/data", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class SecretsController {

  @Autowired
  SecretStore secretStore;

  @Autowired
  SecretGenerator secretGenerator;

  @Autowired
  GeneratorRequestValidator validator;

  private MessageSourceAccessor messageSourceAccessor;

  @Autowired
  private MessageSource messageSource;

  @PostConstruct
  public void init() {
    messageSourceAccessor = new MessageSourceAccessor(messageSource);
  }

  @RequestMapping(path = "/{secretPath}", method = RequestMethod.POST)
  ResponseEntity generate(@PathVariable String secretPath, @Valid @RequestBody GeneratorRequest generatorRequest, BindingResult result) {
    SecretParameters secretParameters = generatorRequest.getParameters();

    if (secretParameters == null) {
      secretParameters = new SecretParameters();
    }
    generatorRequest.setParameters(secretParameters);
    validator.validate(generatorRequest, result);
    if (result.hasErrors()) {
      String key = result.getAllErrors().get(0).getCode();
      return createErrorResponse(key, HttpStatus.BAD_REQUEST);
    }

    String secretValue = secretGenerator.generateSecret(secretParameters);
    Secret secret = new Secret(secretValue, generatorRequest.getType());

    secretStore.set(secretPath, secret);

    return new ResponseEntity<>(secret, HttpStatus.OK);
  }

  @RequestMapping(path = "/{secretPath}", method = RequestMethod.PUT)
  ResponseEntity set(@PathVariable String secretPath, @Valid @RequestBody Secret secret, BindingResult bindingResult) {
    if (secret.getType() == null || bindingResult.hasErrors()) {
      return createErrorResponse("error.secret_type_invalid", HttpStatus.BAD_REQUEST);
    }
    secretStore.set(secretPath, secret);
    return new ResponseEntity<>(secret, HttpStatus.OK);
  }

  @RequestMapping(path = "/{secretPath}", method = RequestMethod.DELETE)
  ResponseEntity delete(@PathVariable String secretPath) {
    Secret secret = secretStore.delete(secretPath);

    if (secret == null) {
      return createErrorResponse("error.secret_not_found", HttpStatus.NOT_FOUND);
    } else {
      return new ResponseEntity(HttpStatus.OK);
    }
  }

  @RequestMapping(path = "/{secretPath}", method = RequestMethod.GET)
  ResponseEntity get(@PathVariable String secretPath) {
    Secret secret = secretStore.get(secretPath);

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
