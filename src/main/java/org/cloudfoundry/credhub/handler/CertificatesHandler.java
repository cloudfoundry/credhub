package org.cloudfoundry.credhub.handler;

import org.cloudfoundry.credhub.audit.AuditingOperationCode;
import org.cloudfoundry.credhub.audit.EventAuditRecordParameters;
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
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class CertificatesHandler {

  private PermissionedCertificateService permissionedCertificateService;
  private UniversalCredentialGenerator credentialGenerator;
  private GenerationRequestGenerator generationRequestGenerator;
  private CertificateService certificateService;

  CertificatesHandler(
      PermissionedCertificateService permissionedCertificateService,
      CertificateService certificateService,
      UniversalCredentialGenerator credentialGenerator,
      GenerationRequestGenerator generationRequestGenerator) {
    this.permissionedCertificateService = permissionedCertificateService;
    this.certificateService = certificateService;
    this.credentialGenerator = credentialGenerator;
    this.generationRequestGenerator = generationRequestGenerator;
  }

  public CredentialView handleRegenerate(
      String credentialUuid,
      List<EventAuditRecordParameters> auditRecordParameters,
      CertificateRegenerateRequest request) {

    CertificateCredentialVersion existingCredentialVersion = certificateService
        .findByCredentialUuid(credentialUuid, auditRecordParameters);

    BaseCredentialGenerateRequest generateRequest = generationRequestGenerator
        .createGenerateRequest(existingCredentialVersion, existingCredentialVersion.getName(), auditRecordParameters);
    CertificateCredentialValue credentialValue = (CertificateCredentialValue) credentialGenerator
        .generate(generateRequest);
    credentialValue.setTransitional(request.isTransitional());

    final CertificateCredentialVersion credentialVersion = (CertificateCredentialVersion) permissionedCertificateService
        .save(
            existingCredentialVersion,
            credentialValue,
            generateRequest,
            auditRecordParameters
        );

    return new CertificateView(credentialVersion);
  }

  public CertificateCredentialsView handleGetAllRequest(List<EventAuditRecordParameters> auditRecordParameters) {
    final List<Credential> credentialList = permissionedCertificateService.getAll(auditRecordParameters);

    List<CertificateCredentialView> list = credentialList.stream().map(credential ->
        new CertificateCredentialView(credential.getName(), credential.getUuid())
    ).collect(Collectors.toList());

    return new CertificateCredentialsView(list);
  }

  public CertificateCredentialsView handleGetByNameRequest(String name,
      List<EventAuditRecordParameters> auditRecordParameters) {
    final List<Credential> credentialList = permissionedCertificateService.getByName(name, auditRecordParameters);

    List<CertificateCredentialView> list = credentialList.stream().map(credential ->
        new CertificateCredentialView(credential.getName(), credential.getUuid())
    ).collect(Collectors.toList());

    return new CertificateCredentialsView(list);
  }

  public List<CertificateView> handleGetAllVersionsRequest(String uuidString,
      List<EventAuditRecordParameters> auditRecordParameters, boolean current) {
    UUID uuid;
    try {
      uuid = UUID.fromString(uuidString);
    } catch (IllegalArgumentException e) {
      auditRecordParameters.add(new EventAuditRecordParameters(AuditingOperationCode.CREDENTIAL_ACCESS, null));
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    final List<CredentialVersion> credentialList = permissionedCertificateService
        .getVersions(uuid, current, auditRecordParameters);

    List<CertificateView> list = credentialList.stream().map(credential ->
        new CertificateView((CertificateCredentialVersion) credential)
    ).collect(Collectors.toList());

    return list;
  }


  public CertificateView handleDeleteVersionRequest(String certificateId, String versionId,
      List<EventAuditRecordParameters> auditRecordParameters) {
    CertificateCredentialVersion deletedVersion = permissionedCertificateService
        .deleteVersion(UUID.fromString(certificateId), UUID.fromString(versionId), auditRecordParameters);
    return new CertificateView(deletedVersion);
  }

  public List<CertificateView> handleUpdateTransitionalVersion(String certificateId, UpdateTransitionalVersionRequest requestBody,
      List<EventAuditRecordParameters> auditRecordParameters) {
    List<CredentialVersion> credentialList;
    UUID versionUUID = null;

    if(requestBody.getVersionUuid() != null) {
      versionUUID = UUID.fromString(requestBody.getVersionUuid());
    }

    credentialList = permissionedCertificateService.updateTransitionalVersion(UUID.fromString(certificateId), versionUUID, auditRecordParameters);


    List<CertificateView> list = credentialList.stream().map(credential ->
        new CertificateView((CertificateCredentialVersion) credential)
    ).collect(Collectors.toList());

    return list;
  }

  public CertificateView handleCreateVersionsRequest(String certificateId, CreateVersionRequest requestBody,
      List<EventAuditRecordParameters> auditRecordParameters) {

    CertificateCredentialValue certificateCredentialValue = requestBody.getValue();
    certificateCredentialValue.setTransitional(requestBody.isTransitional());
    final CertificateCredentialVersion credentialVersion = permissionedCertificateService.set(
        UUID.fromString(certificateId),
        certificateCredentialValue,
        auditRecordParameters
    );

    return new CertificateView(credentialVersion);
  }
}
