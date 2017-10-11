package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.credential.CertificateCredentialValue;
import io.pivotal.security.data.CertificateAuthorityService;
import io.pivotal.security.request.BaseCredentialSetRequest;
import io.pivotal.security.request.CertificateSetRequest;
import io.pivotal.security.request.PasswordSetRequest;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.service.PermissionedCredentialService;
import io.pivotal.security.view.CredentialView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class SetHandler {

  private PermissionedCredentialService credentialService;
  private CertificateAuthorityService certificateAuthorityService;

  @Autowired
  public SetHandler(
      PermissionedCredentialService credentialService,
      CertificateAuthorityService certificateAuthorityService
  ) {
    this.credentialService = credentialService;
    this.certificateAuthorityService = certificateAuthorityService;
  }

  public CredentialView handle(
      BaseCredentialSetRequest setRequest,
      UserContext userContext,
      List<EventAuditRecordParameters> eventAuditRecordParameters
  ) {
    StringGenerationParameters generationParameters = null;

    if (setRequest instanceof PasswordSetRequest) {
      generationParameters = ((PasswordSetRequest) setRequest).getGenerationParameters();
    } else if (setRequest instanceof CertificateSetRequest) {
      // fill in the ca value if it's one of ours
      CertificateCredentialValue certificateValue = ((CertificateSetRequest) setRequest).getCertificateValue();

      String caName = certificateValue.getCaName();
      if (caName != null) {
        certificateValue.setCa(certificateAuthorityService.findMostRecent(userContext, caName).getCertificate());
      }
    }

    return credentialService.save(
        setRequest.getName(),
        setRequest.getType(),
        setRequest.getCredentialValue(),
        generationParameters,
        setRequest.getAdditionalPermissions(),
        setRequest.isOverwrite(),
        userContext,
        eventAuditRecordParameters
    );
  }
}
