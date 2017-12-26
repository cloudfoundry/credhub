package org.cloudfoundry.credhub.controller.v1;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.audit.EventAuditLogService;
import org.cloudfoundry.credhub.handler.CertificatesHandler;
import org.cloudfoundry.credhub.request.CertificateRegenerateRequest;
import org.cloudfoundry.credhub.view.CertificateCredentialsView;
import org.cloudfoundry.credhub.view.CertificateView;
import org.cloudfoundry.credhub.view.CredentialView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.List;

import static org.cloudfoundry.credhub.controller.v1.CertificatesController.API_V1_CERTIFICATES;

@RestController
@RequestMapping(API_V1_CERTIFICATES)
public class CertificateVersionsController {

  static final String API_V1_CERTIFICATES = "api/v1/certificates";

  private final EventAuditLogService eventAuditLogService;
  private CertificatesHandler certificatesHandler;

  @Autowired
  public CertificateVersionsController(
      CertificatesHandler certificateHandler,
      EventAuditLogService eventAuditLogService) {
    this.certificatesHandler = certificateHandler;
    this.eventAuditLogService = eventAuditLogService;
  }

  @GetMapping(value = "/{certificateId}/versions", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public List<CertificateView> getAllVersions(@PathVariable String certificateId,
      @RequestParam(value = "current", required = false, defaultValue = "false") boolean current) throws IOException {
    return eventAuditLogService
        .auditEvents((auditRecordParameters ->
            certificatesHandler.handleGetAllVersionsRequest(certificateId, auditRecordParameters, current)
        ));
  }

  @DeleteMapping(value = "/{certificateId}/versions/{versionId}", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public CertificateView deleteVersion(@PathVariable String certificateId, @PathVariable String versionId) throws IOException {
    return eventAuditLogService
        .auditEvents((auditRecordParameters ->
            certificatesHandler.handleDeleteVersionRequest(certificateId, versionId, auditRecordParameters)
        ));
  }
}
