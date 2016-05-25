package io.pivotal.security.controller.v1;

import io.pivotal.security.entity.ResponseError;
import io.pivotal.security.entity.ResponseErrorType;
import io.pivotal.security.entity.Secret;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.repository.SecretRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import javax.validation.ValidationException;
import java.io.IOException;


@RestController
@RequestMapping(path = "/api/v1/data", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class SecretsController {

  @Autowired
  SecretRepository secretRepository;

  @Autowired
  SecretGenerator secretGenerator;

  @RequestMapping(path = "/{secretPath}", method = RequestMethod.POST)
  Secret generate(@PathVariable String secretPath) {
    String secretValue = secretGenerator.generateSecret();
    Secret secret = new Secret(secretValue);

    secretRepository.set(secretPath, secret);

    return secret;
  }

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
