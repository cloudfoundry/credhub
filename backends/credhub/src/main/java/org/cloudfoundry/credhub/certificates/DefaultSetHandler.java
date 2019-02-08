package org.cloudfoundry.credhub.certificates;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.data.CertificateAuthorityService;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.handlers.SetHandler;
import org.cloudfoundry.credhub.requests.BaseCredentialSetRequest;
import org.cloudfoundry.credhub.requests.CertificateSetRequest;
import org.cloudfoundry.credhub.services.PermissionedCredentialService;
import org.cloudfoundry.credhub.utils.CertificateReader;
import org.cloudfoundry.credhub.views.CredentialView;

@SuppressFBWarnings(
  value = "NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE",
  justification = "This will be refactored into safer non-nullable types"
)
@Component
public class DefaultSetHandler implements SetHandler {

  private final PermissionedCredentialService credentialService;
  private final CertificateAuthorityService certificateAuthorityService;
  private final CEFAuditRecord auditRecord;

  @Autowired
  public DefaultSetHandler(
    final PermissionedCredentialService credentialService,
    final CertificateAuthorityService certificateAuthorityService,
    final CEFAuditRecord auditRecord) {
    super();
    this.credentialService = credentialService;
    this.certificateAuthorityService = certificateAuthorityService;
    this.auditRecord = auditRecord;
  }

  @Override
  public CredentialView handle(final BaseCredentialSetRequest setRequest) {
    if (setRequest instanceof CertificateSetRequest) {
      // fill in the ca value if it's one of ours
      final CertificateCredentialValue certificateValue = ((CertificateSetRequest) setRequest).getCertificateValue();

      final String caName = certificateValue.getCaName();

      if (caName != null) {
        validateCertificateValueIsSignedByCa(certificateValue, caName);
      }
    }

    final CredentialVersion existingCredentialVersion = credentialService.findMostRecent(setRequest.getName());

    final CredentialVersion credentialVersion = credentialService.save(
      existingCredentialVersion,
      setRequest.getCredentialValue(),
      setRequest
    );

    auditRecord.setVersion(credentialVersion);
    auditRecord.setResource(credentialVersion.getCredential());
    return CredentialView.fromEntity(credentialVersion);
  }

  private void validateCertificateValueIsSignedByCa(final CertificateCredentialValue certificateValue, final String caName) {
    final String caValue = certificateAuthorityService.findActiveVersion(caName).getCertificate();
    certificateValue.setCa(caValue);

    final CertificateReader certificateReader = new CertificateReader(certificateValue.getCertificate());

    if (!certificateReader.isSignedByCa(caValue)) {
      throw new ParameterizedValidationException("error.certificate_was_not_signed_by_ca_name");
    }
  }
}
