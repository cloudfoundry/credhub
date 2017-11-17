package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.auth.UserContextHolder;
import io.pivotal.security.credential.CertificateCredentialValue;
import io.pivotal.security.data.CertificateAuthorityService;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.BaseCredentialSetRequest;
import io.pivotal.security.request.CertificateSetRequest;
import io.pivotal.security.request.PasswordSetRequest;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.service.PermissionedCredentialService;
import io.pivotal.security.util.CertificateReader;
import io.pivotal.security.view.CredentialView;
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
    StringGenerationParameters generationParameters = null;
    UserContext userContext = userContextHolder.getUserContext();

    if (setRequest instanceof PasswordSetRequest) {
      generationParameters = ((PasswordSetRequest) setRequest).getGenerationParameters();
    } else if (setRequest instanceof CertificateSetRequest) {
      // fill in the ca value if it's one of ours
      CertificateCredentialValue certificateValue = ((CertificateSetRequest) setRequest).getCertificateValue();

      String caName = certificateValue.getCaName();
      if (caName != null) {
        final String caValue = certificateAuthorityService.findActiveVersion(caName).getCertificate();
        certificateValue.setCa(caValue);

        CertificateReader certificateReader = new CertificateReader(certificateValue.getCertificate());

        if (!certificateReader.isSignedByCa(caValue)){
          throw new ParameterizedValidationException("error.certificate_was_not_signed_by_ca");
        }
      }
    }

    CredentialVersion existingCredentialVersion = credentialService.findMostRecent(setRequest.getName());

    final CredentialVersion credentialVersion = credentialService.save(
        existingCredentialVersion, setRequest.getName(),
        setRequest.getType(),
        setRequest.getCredentialValue(),
        generationParameters,
        setRequest.getAdditionalPermissions(),
        setRequest.getOverwriteMode(),
        auditRecordParameters
    );

    final boolean isNewCredential = existingCredentialVersion == null;

    if (isNewCredential || setRequest.isOverwrite()) {
      permissionService.savePermissions(credentialVersion, setRequest.getAdditionalPermissions(), auditRecordParameters, isNewCredential, setRequest.getName());
    }

    return CredentialView.fromEntity(credentialVersion);
  }
}
