package io.pivotal.security.generator;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.credential.CertificateCredentialValue;
import io.pivotal.security.data.CertificateAuthorityService;
import io.pivotal.security.domain.CertificateGenerationParameters;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.request.GenerationParameters;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.util.CertificateReader;
import io.pivotal.security.util.PrivateKeyReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import static io.pivotal.security.request.PermissionOperation.READ;
import static io.pivotal.security.util.CertificateFormatter.pemOf;

@Component
public class CertificateGenerator implements CredentialGenerator<CertificateCredentialValue> {

  private final LibcryptoRsaKeyPairGenerator keyGenerator;
  private final SignedCertificateGenerator signedCertificateGenerator;
  private final CertificateAuthorityService certificateAuthorityService;
  private PermissionService permissionService;


  @Autowired
  public CertificateGenerator(
      LibcryptoRsaKeyPairGenerator keyGenerator,
      SignedCertificateGenerator signedCertificateGenerator,
      CertificateAuthorityService certificateAuthorityService,
      PermissionService permissionService) {
    this.keyGenerator = keyGenerator;
    this.signedCertificateGenerator = signedCertificateGenerator;
    this.certificateAuthorityService = certificateAuthorityService;
    this.permissionService = permissionService;
  }

  @Override
  public CertificateCredentialValue generateCredential(GenerationParameters p, UserContext userContext) {
    CertificateGenerationParameters params = (CertificateGenerationParameters) p;
    try {
      KeyPair keyPair = keyGenerator.generateKeyPair(params.getKeyLength());
      X509Certificate cert;
      String caName = null;
      String caCertificate = null;
      String privatePem = pemOf(keyPair.getPrivate());

      if (params.isSelfSigned()) {
        cert = signedCertificateGenerator.getSelfSigned(keyPair, params);
      } else {
        caName = params.getCaName();
        if (!permissionService.hasPermission(userContext.getAclUser(), caName, READ)) {
          throw new EntryNotFoundException("error.credential.invalid_access");
        }
        CertificateCredentialValue ca = certificateAuthorityService.findMostRecent(caName);
        caCertificate = ca.getCertificate();

        cert = signedCertificateGenerator.getSignedByIssuer(
            keyPair,
            params,
            CertificateReader.getCertificate(caCertificate),
            PrivateKeyReader.getPrivateKey(ca.getPrivateKey())
          );
      }

      return new CertificateCredentialValue(caCertificate, pemOf(cert), privatePem, caName);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
