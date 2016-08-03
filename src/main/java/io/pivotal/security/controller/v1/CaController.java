package io.pivotal.security.controller.v1;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.generator.BCCertificateGenerator;
import io.pivotal.security.mapper.AuthoritySetterRequestTranslator;
import io.pivotal.security.mapper.CertificateAuthorityRequestTranslatorWithGeneration;
import io.pivotal.security.mapper.CertificateAuthoritySetterRequestTranslator;
import io.pivotal.security.mapper.CertificateGeneratorRequestTranslator;
import io.pivotal.security.repository.InMemoryAuthorityRepository;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.view.CertificateAuthority;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpRequest;
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

import javax.annotation.PostConstruct;
import javax.validation.ValidationException;

@RestController
@RequestMapping(path = "/api/v1/ca", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class CaController {
  @Autowired
  Configuration jsonPathConfiguration;

  @Autowired
  InMemoryAuthorityRepository caRepository;

  private MessageSourceAccessor messageSourceAccessor;

  @Autowired
  private MessageSource messageSource;

  @Autowired
  CertificateAuthoritySetterRequestTranslator certificateAuthoritySetterRequestTranslator;

  @Autowired
  CertificateAuthorityRequestTranslatorWithGeneration certificateAuthorityRequestTranslatorWithGeneration;

  @Autowired
  CertificateGeneratorRequestTranslator certificateGeneratorRequestTranslator;

  @Autowired
  BCCertificateGenerator certificateGenerator;

  @PostConstruct
  public void init() {
    messageSourceAccessor = new MessageSourceAccessor(messageSource);
  }

  @SuppressWarnings("unused")
  @RequestMapping(path = "/{caPath}", method = RequestMethod.PUT)
  ResponseEntity set(@PathVariable String caPath, InputStream requestBody) {
    return storeAuthority(caPath, requestBody, certificateAuthoritySetterRequestTranslator);
  }

  @SuppressWarnings("unused")
  @RequestMapping(path = "/{caPath}", method = RequestMethod.POST)
  ResponseEntity generate(@PathVariable String caPath, InputStream requestBody) {
    return storeAuthority(caPath, requestBody, certificateAuthorityRequestTranslatorWithGeneration);
  }

  private ResponseEntity storeAuthority(@PathVariable String caPath, InputStream requestBody, AuthoritySetterRequestTranslator requestTranslator) {
    DocumentContext parsed = JsonPath.using(jsonPathConfiguration).parse(requestBody);
    CertificateAuthority certificateAuthority;
    try {
      certificateAuthority = requestTranslator.createAuthorityFromJson(parsed);
      NamedCertificateAuthority namedCertificateAuthority = createEntityFromView(caPath, certificateAuthority);
      caRepository.save(namedCertificateAuthority);
      certificateAuthority.setUpdatedAt(namedCertificateAuthority.getUpdatedAt());
    } catch (ValidationException ve) {
      return createErrorResponse(ve.getMessage(), HttpStatus.BAD_REQUEST);
    }

    return new ResponseEntity<>(certificateAuthority, HttpStatus.OK);
  }

  @SuppressWarnings("unused")
  @RequestMapping(path = "/{caPath}", method = RequestMethod.GET)
  ResponseEntity get(@PathVariable String caPath) {
    NamedCertificateAuthority namedAuthority = caRepository.findOneByName(caPath);
    if (namedAuthority == null) {
      return createErrorResponse("error.ca_not_found", HttpStatus.NOT_FOUND);
    }
    CertificateAuthority certificateAuthority = (CertificateAuthority) namedAuthority.generateView();
    return new ResponseEntity<>(certificateAuthority, HttpStatus.OK);
  }

  private NamedCertificateAuthority createEntityFromView(@PathVariable String caPath, CertificateAuthority certificateAuthority) {
    NamedCertificateAuthority namedCertificateAuthority = caRepository.findOneByName(caPath);
    if (namedCertificateAuthority == null) {
      namedCertificateAuthority = new NamedCertificateAuthority(caPath);
    }
    certificateAuthority.populateEntity(namedCertificateAuthority);
    return namedCertificateAuthority;
  }

  @ExceptionHandler({HttpMessageNotReadableException.class, ValidationException.class, com.jayway.jsonpath.InvalidJsonException.class})
  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  public ResponseError handleHttpMessageNotReadableException() throws IOException {
    return new ResponseError(ResponseErrorType.BAD_REQUEST);
  }

  private ResponseEntity createErrorResponse(String key, HttpStatus status) {
    String errorMessage = messageSourceAccessor.getMessage(key);
    return new ResponseEntity<>(Collections.singletonMap("error", errorMessage), status);
  }
}
