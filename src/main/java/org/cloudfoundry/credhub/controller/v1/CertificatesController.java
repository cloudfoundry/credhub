package org.cloudfoundry.credhub.controller.v1;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.audit.EventAuditLogService;
import org.cloudfoundry.credhub.handler.CertificatesHandler;
import org.cloudfoundry.credhub.request.CertificateRegenerateRequest;
import org.cloudfoundry.credhub.view.CertificateCredentialsView;
import org.cloudfoundry.credhub.view.CredentialView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

import static org.cloudfoundry.credhub.controller.v1.CertificatesController.API_V1_CERTIFICATES;

@RestController
@RequestMapping(API_V1_CERTIFICATES)
public class CertificatesController {

  static final String API_V1_CERTIFICATES = "api/v1/certificates";

  private final EventAuditLogService eventAuditLogService;
  private CertificatesHandler certificatesHandler;

  @Autowired
  public CertificatesController(
      CertificatesHandler certificateHandler,
      EventAuditLogService eventAuditLogService) {
    this.certificatesHandler = certificateHandler;
    this.eventAuditLogService = eventAuditLogService;
  }

  @RequestMapping(
      method = RequestMethod.POST,
      value = "/{certificateId}/regenerate",
      produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public CredentialView regenerate(@RequestBody(required = false) CertificateRegenerateRequest requestBody,
      @PathVariable String certificateId) throws IOException {
    if (requestBody == null) {
      requestBody = new CertificateRegenerateRequest();
    }
    CertificateRegenerateRequest finalRequestBody = requestBody;
    return eventAuditLogService
        .auditEvents((auditRecordParameters ->
            certificatesHandler.handleRegenerate(certificateId, auditRecordParameters, finalRequestBody)
        ));
  }

  @RequestMapping(
      method = RequestMethod.GET,
      value = "",
      produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public CertificateCredentialsView getAllCertificates() throws IOException {
    return eventAuditLogService
        .auditEvents((auditRecordParameters ->
          certificatesHandler.handleGetAllRequest(auditRecordParameters)
        ));
  }

  @RequestMapping(
      method = RequestMethod.GET,
      value = "",
      params = "name",
      produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public CertificateCredentialsView getCertificateByName(@RequestParam("name") String name) throws IOException {
    String credentialNameWithPrependedSlash = StringUtils.prependIfMissing(name, "/");
    return eventAuditLogService
        .auditEvents((auditRecordParameters ->
          certificatesHandler.handleGetByNameRequest(credentialNameWithPrependedSlash, auditRecordParameters)
        ));
  }
}
