package io.pivotal.security.controller.v1;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.repository.InMemoryAuthorityRepository;
import io.pivotal.security.view.CertificateAuthority;
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
  InMemoryAuthorityRepository caRepository;

  @PostConstruct
  public void init() {
  }

  @RequestMapping(path = "/{caPath}", method = RequestMethod.PUT)
  ResponseEntity set(@PathVariable String caPath, InputStream requestBody) {
    CertificateAuthority certificateAuthority = createCertificateAuthorityViewFromJson(requestBody);
    NamedCertificateAuthority namedCertificateAuthority = createEntityFromView(caPath, certificateAuthority);

    caRepository.save(namedCertificateAuthority);
    return new ResponseEntity<>(certificateAuthority, HttpStatus.OK);
  }

  private NamedCertificateAuthority createEntityFromView(@PathVariable String caPath, CertificateAuthority certificateAuthority) {
    NamedCertificateAuthority namedCertificateAuthority = new NamedCertificateAuthority(caPath);
    certificateAuthority.populateEntity(namedCertificateAuthority);
    return namedCertificateAuthority;
  }

  private CertificateAuthority createCertificateAuthorityViewFromJson(InputStream requestBody) {
    DocumentContext parsed = JsonPath.using(jsonPathConfiguration).parse(requestBody);
    return new CertificateAuthority(parsed.read("$.root.public"), parsed.read("$.root.private"));
  }

  @ExceptionHandler({HttpMessageNotReadableException.class, ValidationException.class})
  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  public ResponseError handleHttpMessageNotReadableException() throws IOException {
    return new ResponseError(ResponseErrorType.BAD_REQUEST);
  }
}