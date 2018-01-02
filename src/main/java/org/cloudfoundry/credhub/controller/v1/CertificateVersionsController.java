package org.cloudfoundry.credhub.controller.v1;

import org.cloudfoundry.credhub.audit.EventAuditLogService;
import org.cloudfoundry.credhub.handler.CertificatesHandler;
import org.cloudfoundry.credhub.request.CreateVersionRequest;
import org.cloudfoundry.credhub.view.CertificateView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.List;

import static org.cloudfoundry.credhub.controller.v1.CertificateVersionsController.API_V1_CERTIFICATE_VERSIONS;

@RestController
@RequestMapping(API_V1_CERTIFICATE_VERSIONS)
public class CertificateVersionsController {

  static final String API_V1_CERTIFICATE_VERSIONS = "api/v1/certificates/{certificateId}/versions";

  private final EventAuditLogService eventAuditLogService;
  private CertificatesHandler certificatesHandler;

  @Autowired
  public CertificateVersionsController(
      CertificatesHandler certificateHandler,
      EventAuditLogService eventAuditLogService) {
    this.certificatesHandler = certificateHandler;
    this.eventAuditLogService = eventAuditLogService;
  }

  @GetMapping(value = "", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public List<CertificateView> getAllVersions(@PathVariable String certificateId,
      @RequestParam(value = "current", required = false, defaultValue = "false") boolean current) throws IOException {
    return eventAuditLogService
        .auditEvents((auditRecordParameters ->
            certificatesHandler.handleGetAllVersionsRequest(certificateId, auditRecordParameters, current)
        ));
  }

  @PostMapping(value = "", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public CertificateView createVersion(@RequestBody @Validated CreateVersionRequest requestBody,
      @PathVariable String certificateId) throws IOException {
    return eventAuditLogService
        .auditEvents((auditRecordParameters ->
            certificatesHandler.handleCreateVersionsRequest(certificateId, requestBody, auditRecordParameters)
        ));
  }

  @DeleteMapping(value = "/{versionId}", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public CertificateView deleteVersion(@PathVariable String certificateId, @PathVariable String versionId) throws IOException {
    return eventAuditLogService
        .auditEvents((auditRecordParameters ->
            certificatesHandler.handleDeleteVersionRequest(certificateId, versionId, auditRecordParameters)
        ));
  }
}
