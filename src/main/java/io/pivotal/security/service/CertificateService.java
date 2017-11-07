package io.pivotal.security.service;

import io.pivotal.security.audit.AuditingOperationCode;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContextHolder;
import io.pivotal.security.data.CredentialVersionDataService;
import io.pivotal.security.domain.CertificateCredentialVersion;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.request.PermissionOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CertificateService {

  private final CredentialVersionDataService credentialVersionDataService;

  private PermissionCheckingService permissionCheckingService;
  private final UserContextHolder userContextHolder;

  @Autowired
  public CertificateService(
      CredentialVersionDataService credentialVersionDataService,
      PermissionCheckingService permissionCheckingService,
      UserContextHolder userContextHolder) {
    this.credentialVersionDataService = credentialVersionDataService;
    this.permissionCheckingService = permissionCheckingService;
    this.userContextHolder = userContextHolder;
  }

  public CertificateCredentialVersion findByUuid(String uuid,
      List<EventAuditRecordParameters> auditRecordParameters) {
    EventAuditRecordParameters eventAuditRecordParameters = new EventAuditRecordParameters(AuditingOperationCode.CREDENTIAL_ACCESS);
    auditRecordParameters.add(eventAuditRecordParameters);
    CredentialVersion credentialVersion = this.credentialVersionDataService
        .findByUuid(uuid);
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
