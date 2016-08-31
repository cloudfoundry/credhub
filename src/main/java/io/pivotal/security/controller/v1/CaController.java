package io.pivotal.security.controller.v1;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.generator.BCCertificateGenerator;
import io.pivotal.security.mapper.CAGeneratorRequestTranslator;
import io.pivotal.security.mapper.CASetterRequestTranslator;
import io.pivotal.security.mapper.RequestTranslator;
import io.pivotal.security.repository.CertificateAuthorityRepository;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordParameters;
import io.pivotal.security.view.CertificateAuthority;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.core.Authentication;
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
import javax.servlet.http.HttpServletRequest;
import javax.validation.ValidationException;

@RestController
@RequestMapping(path = "/api/v1/ca", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class CaController {
  @Autowired
  Configuration jsonPathConfiguration;

  @Autowired
  CertificateAuthorityRepository caRepository;

  private MessageSourceAccessor messageSourceAccessor;

  @Autowired
  private MessageSource messageSource;

  @Autowired
  CASetterRequestTranslator caSetterRequestTranslator;

  @Autowired
  CAGeneratorRequestTranslator caGeneratorRequestTranslator;

  @Autowired
  BCCertificateGenerator certificateGenerator;

  @Autowired
  AuditLogService auditLogService;

  @PostConstruct
  public void init() {
    messageSourceAccessor = new MessageSourceAccessor(messageSource);
  }

  @SuppressWarnings("unused")
  @RequestMapping(path = "/{caPath}", method = RequestMethod.PUT)
  ResponseEntity set(@PathVariable String caPath, InputStream requestBody, HttpServletRequest request, Authentication authentication) throws Exception {
    return auditLogService.performWithAuditing("ca_update", new AuditRecordParameters(request, authentication), () -> {
      return storeAuthority(caPath, requestBody, caSetterRequestTranslator);
    });
  }

  @SuppressWarnings("unused")
  @RequestMapping(path = "/{caPath}", method = RequestMethod.POST)
  ResponseEntity generate(@PathVariable String caPath, InputStream requestBody, HttpServletRequest request, Authentication authentication) throws Exception {
    return auditLogService.performWithAuditing("ca_update", new AuditRecordParameters(request, authentication), () -> {
      return storeAuthority(caPath, requestBody, caGeneratorRequestTranslator);
    });
  }

  private ResponseEntity storeAuthority(@PathVariable String caPath, InputStream requestBody, RequestTranslator<NamedCertificateAuthority> requestTranslator) {
    DocumentContext parsed = JsonPath.using(jsonPathConfiguration).parse(requestBody);
    NamedCertificateAuthority namedCertificateAuthority = caRepository.findOneByName(caPath);
    if (namedCertificateAuthority == null) {
      namedCertificateAuthority = new NamedCertificateAuthority(caPath);
    }

    try {
      requestTranslator.populateEntityFromJson(namedCertificateAuthority, parsed);
    } catch (ValidationException ve) {
      return createErrorResponse(ve.getMessage(), HttpStatus.BAD_REQUEST);
    }

    NamedCertificateAuthority saved = caRepository.save(namedCertificateAuthority);
    return new ResponseEntity<>(CertificateAuthority.fromEntity(saved), HttpStatus.OK);
  }

  @SuppressWarnings("unused")
  @RequestMapping(path = "/{caPath}", method = RequestMethod.GET)
  ResponseEntity get(@PathVariable String caPath, HttpServletRequest request, Authentication authentication) throws Exception {
    NamedCertificateAuthority namedAuthority = caRepository.findOneByName(caPath);

    return auditLogService.performWithAuditing("ca_access", new AuditRecordParameters(request, authentication), () -> {
      if (namedAuthority == null) {
        return createErrorResponse("error.ca_not_found", HttpStatus.NOT_FOUND);
      }
      return new ResponseEntity<>(CertificateAuthority.fromEntity(namedAuthority), HttpStatus.OK);
    });
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
