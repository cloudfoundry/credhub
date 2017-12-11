package org.cloudfoundry.credhub.handler;

import org.cloudfoundry.credhub.audit.EventAuditRecordParameters;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.data.CertificateAuthorityService;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.request.BaseCredentialSetRequest;
import org.cloudfoundry.credhub.request.CertificateSetRequest;
import org.cloudfoundry.credhub.service.PermissionService;
import org.cloudfoundry.credhub.service.PermissionedCredentialService;
import org.cloudfoundry.credhub.util.CertificateReader;
import org.cloudfoundry.credhub.view.CredentialView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class SetHandler {

  private PermissionedCredentialService credentialService;
  private PermissionService permissionService;
  private CertificateAuthorityService certificateAuthorityService;
  private UserContextHolder userContextHolder;

  @Autowired
  public SetHandler(
      PermissionedCredentialService credentialService,
      PermissionService permissionService, CertificateAuthorityService certificateAuthorityService,
      UserContextHolder userContextHolder) {
    this.credentialService = credentialService;
    this.permissionService = permissionService;
    this.certificateAuthorityService = certificateAuthorityService;
    this.userContextHolder = userContextHolder;
  }

  public CredentialView handle(
      BaseCredentialSetRequest setRequest,
      List<EventAuditRecordParameters> auditRecordParameters
  ) {

    if (setRequest instanceof CertificateSetRequest) {
      // fill in the ca value if it's one of ours
      CertificateCredentialValue certificateValue = ((CertificateSetRequest) setRequest).getCertificateValue();

      String caName = certificateValue.getCaName();
      if (caName != null) {
        final String caValue = certificateAuthorityService.findActiveVersion(caName).getCertificate();
        certificateValue.setCa(caValue);

        CertificateReader certificateReader = new CertificateReader(certificateValue.getCertificate());

        if (!certificateReader.isSignedByCa(caValue)) {
          throw new ParameterizedValidationException("error.certificate_was_not_signed_by_ca_name");
        }
      }
    }

    CredentialVersion existingCredentialVersion = credentialService.findMostRecent(setRequest.getName());

    final CredentialVersion credentialVersion = credentialService.save(
        existingCredentialVersion,
        setRequest.getCredentialValue(),
        setRequest,
        auditRecordParameters
    );

    final boolean isNewCredential = existingCredentialVersion == null;

    if (isNewCredential || setRequest.isOverwrite()) {
      permissionService.savePermissions(credentialVersion, setRequest.getAdditionalPermissions(), auditRecordParameters, isNewCredential, setRequest.getName());
    }

    return CredentialView.fromEntity(credentialVersion);
  }
}
