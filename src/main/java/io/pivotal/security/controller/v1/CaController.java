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
import io.pivotal.security.view.DataResponse;
import io.pivotal.security.view.ParameterizedValidationException;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import static com.google.common.collect.Lists.newArrayList;
import static io.pivotal.security.constants.AuditingOperationCodes.AUTHORITY_ACCESS;
import static io.pivotal.security.constants.AuditingOperationCodes.AUTHORITY_UPDATE;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

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
    DocumentContext parsedRequest = jsonPath.parse(requestBody);
    return auditLogService.performWithAuditing(AUTHORITY_UPDATE, new AuditRecordParameters(request, authentication), () -> {
      return storeAuthority(parsedRequest, caSetterRequestTranslator);
    });
  }

  @SuppressWarnings("unused")
  @RequestMapping(path = "/**", method = RequestMethod.POST)
  ResponseEntity generate(InputStream requestBody, HttpServletRequest request, Authentication authentication) throws Exception {
    DocumentContext parsedRequest = jsonPath.parse(requestBody);

    return auditLogService.performWithAuditing(AUTHORITY_UPDATE, new AuditRecordParameters(request, authentication), () -> {
      return storeAuthority(parsedRequest, caGeneratorRequestTranslator);
    });
  }

  private ResponseEntity storeAuthority(DocumentContext parsedRequest, RequestTranslator<NamedCertificateAuthority> requestTranslator) {
    String caPath = parsedRequest.read("$.name");

    NamedCertificateAuthority namedCertificateAuthority = new NamedCertificateAuthority(caPath);
    NamedCertificateAuthority mostRecentCA = namedCertificateAuthorityDataService.findMostRecent(caPath);

    if (mostRecentCA != null) {
      mostRecentCA.copyInto(namedCertificateAuthority);
    }

    try {
      requestTranslator.validateJsonKeys(parsedRequest);
      requestTranslator.populateEntityFromJson(namedCertificateAuthority, parsedRequest);
    } catch (ParameterizedValidationException ve) {
      return createParameterizedErrorResponse(ve, HttpStatus.BAD_REQUEST);
    }

    NamedCertificateAuthority saved = namedCertificateAuthorityDataService.save(namedCertificateAuthority);

    return new ResponseEntity<>(CertificateAuthority.fromEntity(saved), HttpStatus.OK);
  }

  @SuppressWarnings("unused")
  @RequestMapping(path = "/**", method = RequestMethod.GET)
  public ResponseEntity getById(HttpServletRequest request, Authentication authentication) throws Exception {
    return retrieveAuthorityWithAuditing(
        caPath(request),
        findAsList(namedCertificateAuthorityDataService::findByUuid),
        request,
        authentication,
        (caList) -> caList.get(0));
  }

  @RequestMapping(path = "", method = RequestMethod.GET)
  public ResponseEntity getByName(
      @RequestParam(name = "name", defaultValue="", required = false) String name,
      @RequestParam(name = "current", defaultValue="false", required = false) Boolean limitResults,
      HttpServletRequest request,
      Authentication authentication) throws Exception {

    if (StringUtils.isEmpty(name)) {
      return createErrorResponse("error.no_identifier", HttpStatus.BAD_REQUEST);
    }

    return retrieveAuthorityWithAuditing(name, getFinder(limitResults), request, authentication, (caList) -> new DataResponse(caList));
  }

  @ExceptionHandler({HttpMessageNotReadableException.class, ParameterizedValidationException.class, com.jayway.jsonpath.InvalidJsonException.class})
  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  public ResponseError handleHttpMessageNotReadableException() throws IOException {
    return new ResponseError(ResponseErrorType.BAD_REQUEST);
  }

  private Function<String, List<NamedCertificateAuthority>> getFinder(Boolean limitResults) {
    if (limitResults) {
      return findAsList(namedCertificateAuthorityDataService::findMostRecent);
    } else {
      return namedCertificateAuthorityDataService::findAllByName;
    }
  }

  private Function<String, List<NamedCertificateAuthority>> findAsList(Function<String, NamedCertificateAuthority> finder) {
    return (toFind) -> {
      NamedCertificateAuthority certificateAuthority = finder.apply(toFind);
      return certificateAuthority != null ? newArrayList(certificateAuthority) : newArrayList();
    };
  }

  private ResponseEntity retrieveAuthorityWithAuditing(
      String identifier,
      Function<String, List<NamedCertificateAuthority>> finder,
      HttpServletRequest request,
      Authentication authentication,
      Function<List<CertificateAuthority>, ?> presenter) throws Exception {
    return auditLogService.performWithAuditing(
        AUTHORITY_ACCESS,
        new AuditRecordParameters(request, authentication),
        () -> {
          List<NamedCertificateAuthority> namedAuthorityList = finder.apply(identifier);

          if (namedAuthorityList.isEmpty()) {
            return createErrorResponse("error.ca_not_found", HttpStatus.NOT_FOUND);
          }

          List<CertificateAuthority> certificateAuthorities = namedAuthorityList.stream().map(
              namedCertificateAuthority -> new CertificateAuthority(namedCertificateAuthority)
          ).collect(Collectors.toList());

          return new ResponseEntity<>(presenter.apply(certificateAuthorities), HttpStatus.OK);
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
