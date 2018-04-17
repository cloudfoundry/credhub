package org.cloudfoundry.credhub.controller.v1;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.audit.EventAuditLogService;
import org.cloudfoundry.credhub.audit.OperationDeviceAction;
import org.cloudfoundry.credhub.audit.entity.GetCertificateByName;
import org.cloudfoundry.credhub.audit.entity.RegenerateCertificate;
import org.cloudfoundry.credhub.audit.entity.UpdateTransitionalVersion;
import org.cloudfoundry.credhub.handler.CertificatesHandler;
import org.cloudfoundry.credhub.request.CertificateRegenerateRequest;
import org.cloudfoundry.credhub.request.UpdateTransitionalVersionRequest;
import org.cloudfoundry.credhub.view.CertificateCredentialsView;
import org.cloudfoundry.credhub.view.CertificateView;
import org.cloudfoundry.credhub.view.CredentialView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static org.cloudfoundry.credhub.controller.v1.CertificatesController.API_V1_CERTIFICATES;

@RestController
@RequestMapping(API_V1_CERTIFICATES)
public class CertificatesController {

  static final String API_V1_CERTIFICATES = "api/v1/certificates";

  private final EventAuditLogService eventAuditLogService;
  private CEFAuditRecord auditRecord;
  private CertificatesHandler certificatesHandler;

  @Autowired
  public CertificatesController(
      CertificatesHandler certificateHandler,
      EventAuditLogService eventAuditLogService,
      CEFAuditRecord auditRecord) {
    this.certificatesHandler = certificateHandler;
    this.eventAuditLogService = eventAuditLogService;
    this.auditRecord = auditRecord;
  }

  @PostMapping(value = "/{certificateId}/regenerate", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public CredentialView regenerate(@RequestBody(required = false) CertificateRegenerateRequest requestBody,
      @PathVariable String certificateId) {
    if (requestBody == null) {
      requestBody = new CertificateRegenerateRequest();
    }
    CertificateRegenerateRequest finalRequestBody = requestBody;

    RegenerateCertificate certificate = new RegenerateCertificate();
    certificate.setTransitional(requestBody.isTransitional());
    auditRecord.setRequestDetails(certificate);

    return eventAuditLogService
        .auditEvents((auditRecordParameters ->
            certificatesHandler.handleRegenerate(certificateId, finalRequestBody)
        ));
  }

  @GetMapping(value = "", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public CertificateCredentialsView getAllCertificates() {
    auditRecord.setRequestDetails(() -> OperationDeviceAction.GET_ALL_CERTIFICATES);

    return eventAuditLogService
        .auditEvents((auditRecordParameters ->
          certificatesHandler.handleGetAllRequest()
        ));
  }

  @PutMapping(value = "/{certificateId}/update_transitional_version", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public List<CertificateView> updateTransitionalVersion(@RequestBody UpdateTransitionalVersionRequest requestBody,
      @PathVariable String certificateId) {
    UpdateTransitionalVersion details = new UpdateTransitionalVersion();
    details.setVersion(requestBody.getVersionUuid());
    auditRecord.setRequestDetails(details);
    return eventAuditLogService
        .auditEvents((auditRecordParameters ->
            certificatesHandler.handleUpdateTransitionalVersion(certificateId, requestBody)
        ));
  }

  @GetMapping(value = "", params = "name", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public CertificateCredentialsView getCertificateByName(@RequestParam("name") String name) {
    String credentialNameWithPrependedSlash = StringUtils.prependIfMissing(name, "/");
    GetCertificateByName details = new GetCertificateByName();
    details.setName(name);
    auditRecord.setRequestDetails(details);
    return eventAuditLogService
        .auditEvents((auditRecordParameters ->
          certificatesHandler.handleGetByNameRequest(credentialNameWithPrependedSlash)
        ));
  }
}
