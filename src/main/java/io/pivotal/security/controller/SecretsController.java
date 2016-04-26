package io.pivotal.security.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "/api/secret", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class SecretsController {

    @RequestMapping(path = "/{secretPath}", method = RequestMethod.PUT)
    ResponseEntity<String> add(@PathVariable String secretPath, @RequestBody String input) {
        return new ResponseEntity<String>(input, null, HttpStatus.OK);
    }

}
