package org.cloudfoundry.credhub.controller.v1;

import java.util.List;

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

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
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

import static org.cloudfoundry.credhub.controller.v1.CertificatesController.API_V1_CERTIFICATES;

@RestController
@RequestMapping(API_V1_CERTIFICATES)
public class CertificatesController {

  public static final String API_V1_CERTIFICATES = "api/v1/certificates";

  private final CEFAuditRecord auditRecord;
  private final CertificatesHandler certificatesHandler;

  @Autowired
  public CertificatesController(final CertificatesHandler certificateHandler, final CEFAuditRecord auditRecord) {
    super();
    this.certificatesHandler = certificateHandler;
    this.auditRecord = auditRecord;
  }

  @PostMapping(value = "/{certificateId}/regenerate", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public CredentialView regenerate(
    @RequestBody(required = false) final CertificateRegenerateRequest requestBody,
    @PathVariable final String certificateId
  ) {
    final CertificateRegenerateRequest finalRequestBody = requestBody == null ? new CertificateRegenerateRequest() : requestBody;

    final RegenerateCertificate certificate = new RegenerateCertificate();
    certificate.setTransitional(finalRequestBody.isTransitional());
    auditRecord.setRequestDetails(certificate);

    return certificatesHandler.handleRegenerate(certificateId, finalRequestBody);
  }

  @GetMapping(value = "", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public CertificateCredentialsView getAllCertificates() {
    auditRecord.setRequestDetails(() -> OperationDeviceAction.GET_ALL_CERTIFICATES);

    return certificatesHandler.handleGetAllRequest();
  }

  @PutMapping(value = "/{certificateId}/update_transitional_version", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public List<CertificateView> updateTransitionalVersion(@RequestBody final UpdateTransitionalVersionRequest requestBody,
                                                         @PathVariable final String certificateId) {
    final UpdateTransitionalVersion details = new UpdateTransitionalVersion();
    details.setVersion(requestBody.getVersionUuid());
    auditRecord.setRequestDetails(details);
    return certificatesHandler.handleUpdateTransitionalVersion(certificateId, requestBody);
  }

  @GetMapping(value = "", params = "name", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public CertificateCredentialsView getCertificateByName(@RequestParam("name") final String name) {
    final String credentialNameWithPrependedSlash = StringUtils.prependIfMissing(name, "/");
    final GetCertificateByName details = new GetCertificateByName();
    details.setName(name);
    auditRecord.setRequestDetails(details);
    return certificatesHandler.handleGetByNameRequest(credentialNameWithPrependedSlash);
  }
}
