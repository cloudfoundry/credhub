package io.pivotal.security.controller.v1;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedRootCertificateSecret;
import io.pivotal.security.repository.InMemorySecretRepository;
import io.pivotal.security.view.RootCertificateSecret;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.*;

import javax.annotation.PostConstruct;
import javax.validation.ValidationException;
import java.io.IOException;
import java.io.InputStream;

@RestController
@RequestMapping(path = "/api/v1/ca", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class CaController {
  @Autowired
  Configuration jsonPathConfiguration;

  @Autowired
  InMemorySecretRepository caRepository;

  @PostConstruct
  public void init() {
  }

  @RequestMapping(path = "/{caPath}", method = RequestMethod.PUT)
  ResponseEntity set(@PathVariable String caPath, InputStream requestBody) {
    DocumentContext parsed = JsonPath.using(jsonPathConfiguration).parse(requestBody);
    // make view
    RootCertificateSecret rootCertificateSecret = new RootCertificateSecret(parsed.read("$.root.public"), parsed.read("$.root.private"));

    // make entity from view
    NamedRootCertificateSecret namedRootCertificateSecret = new NamedRootCertificateSecret(caPath);
    rootCertificateSecret.populateEntity(namedRootCertificateSecret);

    // store entity
    caRepository.save(namedRootCertificateSecret);
    // return view
    return new ResponseEntity<>(rootCertificateSecret, HttpStatus.OK);
  }

  @ExceptionHandler({HttpMessageNotReadableException.class, ValidationException.class})
  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  public ResponseError handleHttpMessageNotReadableException() throws IOException {
    return new ResponseError(ResponseErrorType.BAD_REQUEST);
  }
}
