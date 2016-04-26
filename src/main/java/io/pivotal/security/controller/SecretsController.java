package io.pivotal.security.controller;

import io.pivotal.security.entity.Secret;
import io.pivotal.security.repository.SecretRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "/api/secret", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class SecretsController {

    @Autowired
    SecretRepository secretRepository;

    @RequestMapping(path = "/{secretPath}", method = RequestMethod.PUT)
    Secret add(@PathVariable String secretPath, @RequestBody Secret secret) {
        secretRepository.set(secretPath, secret);
        return secret;
    }

    @RequestMapping(path = "/{secretPath}", method = RequestMethod.GET)
    Secret get(@PathVariable String secretPath) {
        return secretRepository.get(secretPath);
    }

}
