package io.pivotal.security.controller;

import io.pivotal.security.entity.ResponseError;
import io.pivotal.security.entity.ResponseErrorType;
import io.pivotal.security.entity.Secret;
import io.pivotal.security.repository.SecretRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import javax.validation.ValidationException;
import java.io.IOException;

@RestController
@RequestMapping(path = "/api/secret", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class SecretsController {

    @Autowired
    SecretRepository secretRepository;

    @RequestMapping(path = "/{secretPath}", method = RequestMethod.PUT)
    Secret add(@PathVariable String secretPath, @Valid @RequestBody Secret secret) {
        secretRepository.set(secretPath, secret);
        return secret;
    }

    @RequestMapping(path = "/{secretPath}", method = RequestMethod.DELETE)
    void delete(@PathVariable String secretPath) {
        secretRepository.delete(secretPath);
    }

    @RequestMapping(path = "/{secretPath}", method = RequestMethod.GET)
    Secret get(@PathVariable String secretPath) {
        return secretRepository.get(secretPath);
    }

    @ExceptionHandler({HttpMessageNotReadableException.class, ValidationException.class})
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public ResponseError handleHttpMessageNotReadableException() throws IOException {
        return new ResponseError(ResponseErrorType.BAD_REQUEST);
    }
}
