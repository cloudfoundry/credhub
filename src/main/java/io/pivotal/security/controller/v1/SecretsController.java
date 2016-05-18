package io.pivotal.security.controller.v1;

import io.pivotal.security.entity.ResponseError;
import io.pivotal.security.entity.ResponseErrorType;
import io.pivotal.security.entity.Secret;
import io.pivotal.security.repository.SecretRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import javax.validation.Valid;
import javax.validation.ValidationException;


@RestController
@RequestMapping(path = "/api/v1/data", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class SecretsController {

  @Autowired
  SecretRepository secretRepository;

  @RequestMapping(path = "/{secretPath}", method = RequestMethod.PUT)
  Secret add(@PathVariable String secretPath, @Valid @RequestBody Secret secret) {
    secretRepository.set(secretPath, secret);
    return secret;
  }

  @RequestMapping(path = "/{secretPath}", method = RequestMethod.DELETE)
  ResponseEntity delete(@PathVariable String secretPath) {
    Secret secret = secretRepository.delete(secretPath);

    HttpStatus code = (secret == null) ? HttpStatus.NOT_FOUND : HttpStatus.OK;

    return new ResponseEntity(code);
  }

  @RequestMapping(path = "/{secretPath}", method = RequestMethod.GET)
  ResponseEntity<Secret> get(@PathVariable String secretPath) {
    Secret secret = secretRepository.get(secretPath);

    HttpStatus code = (secret == null) ? HttpStatus.NOT_FOUND : HttpStatus.OK;

    return new ResponseEntity<>(secret, code);
  }

  @ExceptionHandler({HttpMessageNotReadableException.class, ValidationException.class})
  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  public ResponseError handleHttpMessageNotReadableException() throws IOException {
    return new ResponseError(ResponseErrorType.BAD_REQUEST);
  }
}
