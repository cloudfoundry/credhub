package io.pivotal.security.controller.v1;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.data.NamedCertificateAuthorityDataService;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.generator.BCCertificateGenerator;
import io.pivotal.security.mapper.CAGeneratorRequestTranslator;
import io.pivotal.security.mapper.CASetterRequestTranslator;
import io.pivotal.security.mapper.RequestTranslator;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordParameters;
import io.pivotal.security.view.CertificateAuthority;
import io.pivotal.security.view.ParameterizedValidationException;
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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import static io.pivotal.security.constants.AuditingOperationCodes.AUTHORITY_ACCESS;
import static io.pivotal.security.constants.AuditingOperationCodes.AUTHORITY_UPDATE;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.Map;
import java.util.function.Function;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping(path = CaController.API_V1_CA, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class CaController {

  public static final String API_V1_CA = "/api/v1/ca";

  @Autowired
  ParseContext jsonPath;

  @Autowired
  NamedCertificateAuthorityDataService namedCertificateAuthorityDataService;

  private MessageSourceAccessor messageSourceAccessor;

  @Autowired
  MessageSource messageSource;

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
  @RequestMapping(path = "/**", method = RequestMethod.PUT)
  ResponseEntity set(InputStream requestBody, HttpServletRequest request, Authentication authentication) throws Exception {
    return auditLogService.performWithAuditing(AUTHORITY_UPDATE, new AuditRecordParameters(request, authentication), () -> {
      return storeAuthority(caPath(request), requestBody, caSetterRequestTranslator);
    });
  }

  @SuppressWarnings("unused")
  @RequestMapping(path = "/**", method = RequestMethod.POST)
  ResponseEntity generate(InputStream requestBody, HttpServletRequest request, Authentication authentication) throws Exception {
    return auditLogService.performWithAuditing(AUTHORITY_UPDATE, new AuditRecordParameters(request, authentication), () -> {
      return storeAuthority(caPath(request), requestBody, caGeneratorRequestTranslator);
    });
  }

  private ResponseEntity storeAuthority(@PathVariable String caPath, InputStream requestBody, RequestTranslator<NamedCertificateAuthority> requestTranslator) {
    DocumentContext parsedRequest = jsonPath.parse(requestBody);
    NamedCertificateAuthority namedCertificateAuthority = namedCertificateAuthorityDataService.find(caPath);
    if (namedCertificateAuthority == null) {
      namedCertificateAuthority = new NamedCertificateAuthority(caPath);
    }

    try {
      requestTranslator.populateEntityFromJson(namedCertificateAuthority, parsedRequest);
      requestTranslator.validateJsonKeys(parsedRequest);
    } catch (ParameterizedValidationException ve) {
      return createParameterizedErrorResponse(ve, HttpStatus.BAD_REQUEST);
    }

    NamedCertificateAuthority saved = namedCertificateAuthorityDataService.save(namedCertificateAuthority);
    String privateKey = namedCertificateAuthorityDataService.getPrivateKeyClearText(namedCertificateAuthority);

    return new ResponseEntity<>(CertificateAuthority.fromEntity(saved, privateKey), HttpStatus.OK);
  }

  @SuppressWarnings("unused")
  @RequestMapping(path = "/**", method = RequestMethod.GET)
  public ResponseEntity getByName(HttpServletRequest request, Authentication authentication) throws Exception {
    return retrieveAuthorityWithAuditing(
        caPath(request),
        namedCertificateAuthorityDataService::find,
        request,
        authentication);
  }

  @RequestMapping(path = "", params = "id", method = RequestMethod.GET)
  public ResponseEntity getById(
      @RequestParam Map<String, String> params,
      HttpServletRequest request,
      Authentication authentication) throws Exception {
    return retrieveAuthorityWithAuditing(
        params.get("id"),
        namedCertificateAuthorityDataService::findOneByUuid,
        request,
        authentication);
  }

  @ExceptionHandler({HttpMessageNotReadableException.class, ParameterizedValidationException.class, com.jayway.jsonpath.InvalidJsonException.class})
  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  public ResponseError handleHttpMessageNotReadableException() throws IOException {
    return new ResponseError(ResponseErrorType.BAD_REQUEST);
  }

  private ResponseEntity retrieveAuthorityWithAuditing(
      String identifier,
      Function<String, NamedCertificateAuthority> finder,
      HttpServletRequest request,
      Authentication authentication) throws Exception {
    return auditLogService.performWithAuditing(
        AUTHORITY_ACCESS,
        new AuditRecordParameters(request, authentication),
        () -> {
          NamedCertificateAuthority namedAuthority = finder.apply(identifier);

          if (namedAuthority == null) {
            return createErrorResponse("error.ca_not_found", HttpStatus.NOT_FOUND);
          }

          String privateKeyClearText = namedCertificateAuthorityDataService.getPrivateKeyClearText(namedAuthority);
          return new ResponseEntity<>(CertificateAuthority.fromEntity(namedAuthority, privateKeyClearText), HttpStatus.OK);
        });
  }

  private String caPath(HttpServletRequest request) {
    return request.getRequestURI().replace(API_V1_CA + "/", "");
  }

  private ResponseEntity createErrorResponse(String key, HttpStatus status) {
    String errorMessage = messageSourceAccessor.getMessage(key);
    return new ResponseEntity<>(Collections.singletonMap("error", errorMessage), status);
  }

  private ResponseEntity createParameterizedErrorResponse(ParameterizedValidationException exception, HttpStatus status) {
    String errorMessage = messageSourceAccessor.getMessage(exception.getMessage(), exception.getParameters());
    return new ResponseEntity<>(Collections.singletonMap("error", errorMessage), status);
  }
}
