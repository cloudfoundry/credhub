package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.audit.AuditingOperationCode;
import org.cloudfoundry.credhub.audit.EventAuditRecordParameters;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.data.CertificateVersionDataService;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CertificateService {

  private final CertificateVersionDataService certificateVersionDataService;

  private PermissionCheckingService permissionCheckingService;
  private final UserContextHolder userContextHolder;

  @Autowired
  public CertificateService(
      CertificateVersionDataService certificateVersionDataService,
      PermissionCheckingService permissionCheckingService,
      UserContextHolder userContextHolder) {
    this.certificateVersionDataService = certificateVersionDataService;
    this.permissionCheckingService = permissionCheckingService;
    this.userContextHolder = userContextHolder;
  }

  public CertificateCredentialVersion findByCredentialUuid(String uuid,
      List<EventAuditRecordParameters> auditRecordParameters) {
    EventAuditRecordParameters eventAuditRecordParameters = new EventAuditRecordParameters(AuditingOperationCode.CREDENTIAL_ACCESS);
    auditRecordParameters.add(eventAuditRecordParameters);

    CredentialVersion credentialVersion = this.certificateVersionDataService
        .findByCredentialUUID(uuid);

    if(credentialVersion == null || !(credentialVersion instanceof CertificateCredentialVersion)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    eventAuditRecordParameters.setCredentialName(credentialVersion.getName());
    CertificateCredentialVersion certificate = (CertificateCredentialVersion) credentialVersion;
    if (!permissionCheckingService.hasPermission(userContextHolder.getUserContext().getActor(), certificate.getName(), PermissionOperation.READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    return certificate;
  }
}
