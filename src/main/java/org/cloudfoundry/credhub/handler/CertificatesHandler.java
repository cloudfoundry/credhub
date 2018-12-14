package org.cloudfoundry.credhub.handler;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.request.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.request.CertificateRegenerateRequest;
import org.cloudfoundry.credhub.request.CreateVersionRequest;
import org.cloudfoundry.credhub.request.UpdateTransitionalVersionRequest;
import org.cloudfoundry.credhub.service.CertificateService;
import org.cloudfoundry.credhub.service.PermissionedCertificateService;
import org.cloudfoundry.credhub.view.CertificateCredentialView;
import org.cloudfoundry.credhub.view.CertificateCredentialsView;
import org.cloudfoundry.credhub.view.CertificateView;
import org.cloudfoundry.credhub.view.CredentialView;

@Service
public class CertificatesHandler {

  private final PermissionedCertificateService permissionedCertificateService;
  private final UniversalCredentialGenerator credentialGenerator;
  private final GenerationRequestGenerator generationRequestGenerator;
  private final CEFAuditRecord auditRecord;
  private final CertificateService certificateService;

  CertificatesHandler(
    final PermissionedCertificateService permissionedCertificateService,
    final CertificateService certificateService,
    final UniversalCredentialGenerator credentialGenerator,
    final GenerationRequestGenerator generationRequestGenerator,
    final CEFAuditRecord auditRecord) {
    super();
    this.permissionedCertificateService = permissionedCertificateService;
    this.certificateService = certificateService;
    this.credentialGenerator = credentialGenerator;
    this.generationRequestGenerator = generationRequestGenerator;
    this.auditRecord = auditRecord;
  }

  public CredentialView handleRegenerate(
    final String credentialUuid,
    final CertificateRegenerateRequest request) {

    final CertificateCredentialVersion existingCredentialVersion = certificateService
      .findByCredentialUuid(credentialUuid);

    final BaseCredentialGenerateRequest generateRequest = generationRequestGenerator
      .createGenerateRequest(existingCredentialVersion);
    final CertificateCredentialValue credentialValue = (CertificateCredentialValue) credentialGenerator
      .generate(generateRequest);
    credentialValue.setTransitional(request.isTransitional());

    final CertificateCredentialVersion credentialVersion = (CertificateCredentialVersion) permissionedCertificateService
      .save(
        existingCredentialVersion,
        credentialValue,
        generateRequest
      );

    auditRecord.setVersion(credentialVersion);

    return new CertificateView(credentialVersion);
  }

  public CertificateCredentialsView handleGetAllRequest() {
    final List<Credential> credentialList = permissionedCertificateService.getAll();

    final List<CertificateCredentialView> list = credentialList.stream().map(credential ->
      new CertificateCredentialView(credential.getName(), credential.getUuid())
    ).collect(Collectors.toList());

    auditRecord.addAllCredentials(credentialList);
    return new CertificateCredentialsView(list);
  }

  public CertificateCredentialsView handleGetByNameRequest(final String name) {
    final List<Credential> credentialList = permissionedCertificateService.getByName(name);

    final List<CertificateCredentialView> list = credentialList.stream().map(credential ->
      new CertificateCredentialView(credential.getName(), credential.getUuid())
    ).collect(Collectors.toList());

    return new CertificateCredentialsView(list);
  }

  public List<CertificateView> handleGetAllVersionsRequest(final String uuidString, final boolean current) {
    final UUID uuid;
    try {
      uuid = UUID.fromString(uuidString);
    } catch (final IllegalArgumentException e) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    final List<CredentialVersion> credentialList = permissionedCertificateService
      .getVersions(uuid, current);

    return credentialList
      .stream()
      .map(credential ->
        new CertificateView((CertificateCredentialVersion) credential)
      ).collect(Collectors.toList());
  }


  public CertificateView handleDeleteVersionRequest(final String certificateId, final String versionId) {
    final CertificateCredentialVersion deletedVersion = permissionedCertificateService
      .deleteVersion(UUID.fromString(certificateId), UUID.fromString(versionId));
    return new CertificateView(deletedVersion);
  }

  public List<CertificateView> handleUpdateTransitionalVersion(final String certificateId,
                                                               final UpdateTransitionalVersionRequest requestBody) {
    UUID versionUUID = null;

    if (requestBody.getVersionUuid() != null) {
      versionUUID = UUID.fromString(requestBody.getVersionUuid());
    }

    final List<CredentialVersion> credentialList;
    credentialList = permissionedCertificateService
      .updateTransitionalVersion(UUID.fromString(certificateId), versionUUID);

    return credentialList
      .stream()
      .map(credential ->
        new CertificateView((CertificateCredentialVersion) credential)
      ).collect(Collectors.toList());
  }

  public CertificateView handleCreateVersionsRequest(final String certificateId, final CreateVersionRequest requestBody) {
    final CertificateCredentialValue certificateCredentialValue = requestBody.getValue();
    certificateCredentialValue.setTransitional(requestBody.isTransitional());
    final CertificateCredentialVersion credentialVersion = permissionedCertificateService.set(
      UUID.fromString(certificateId),
      certificateCredentialValue
    );

    return new CertificateView(credentialVersion);
  }
}
