package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.credential.CertificateCredentialValue;
import io.pivotal.security.data.CertificateAuthorityService;
import io.pivotal.security.request.BaseCredentialSetRequest;
import io.pivotal.security.request.CertificateSetRequest;
import io.pivotal.security.request.PasswordSetRequest;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.service.CredentialService;
import io.pivotal.security.view.CredentialView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class SetRequestHandler {

  private CredentialService credentialService;
  private CertificateAuthorityService certificateAuthorityService;

  @Autowired
  public SetRequestHandler(
      CredentialService credentialService,
      CertificateAuthorityService certificateAuthorityService
  ) {
    this.credentialService = credentialService;
    this.certificateAuthorityService = certificateAuthorityService;
  }

  public CredentialView handle(
      BaseCredentialSetRequest setRequest,
      UserContext userContext,
      PermissionEntry currentEntry,
      List<EventAuditRecordParameters> eventAuditRecordParameters
  ) {
    StringGenerationParameters generationParameters = null;

    if (setRequest instanceof PasswordSetRequest) {
      generationParameters = ((PasswordSetRequest) setRequest).getGenerationParameters();
    } else if (setRequest instanceof CertificateSetRequest) {
      CertificateSetRequest certificateSetRequest = (CertificateSetRequest) setRequest;
      CertificateCredentialValue certificateValue = certificateSetRequest.getCertificateValue();

      if (certificateValue.getCaName() != null) {
        CertificateCredentialValue certificateAuthority = certificateAuthorityService.findMostRecent(certificateValue.getCaName());

        certificateSetRequest.setCertificateValue(
            new CertificateCredentialValue(
                certificateAuthority.getCertificate(),
                certificateValue.getCertificate(),
                certificateValue.getPrivateKey(),
                certificateValue.getCaName()
            )
        );

        setRequest = certificateSetRequest;
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
        currentEntry,
        eventAuditRecordParameters
    );
  }
}
