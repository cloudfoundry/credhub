package org.cloudfoundry.credhub.generators;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.requests.GenerationParameters;
import org.cloudfoundry.credhub.services.CertificateAuthorityService;
import org.cloudfoundry.credhub.utils.CertificateFormatter;
import org.cloudfoundry.credhub.utils.CertificateReader;
import org.cloudfoundry.credhub.utils.PrivateKeyReader;

@Component
public class CertificateGenerator implements CredentialGenerator<CertificateCredentialValue> {

  private final RsaKeyPairGenerator keyGenerator;
  private final SignedCertificateGenerator signedCertificateGenerator;
  private final CertificateAuthorityService certificateAuthorityService;
  private final int caMinimumDurationInDays;
  private final int leafMinimumDurationInDays;


  @Autowired
  public CertificateGenerator(
    final RsaKeyPairGenerator keyGenerator,
    final SignedCertificateGenerator signedCertificateGenerator,
    final CertificateAuthorityService certificateAuthorityService,
    @Value("${certificates.ca_minimum_duration_in_days:#{0}}") final int caMinimumDurationInDays,
    @Value("${certificates.leaf_minimum_duration_in_days:#{0}}") final int leafMinimumDurationInDays) {
    super();
    this.keyGenerator = keyGenerator;
    this.signedCertificateGenerator = signedCertificateGenerator;
    this.certificateAuthorityService = certificateAuthorityService;
    this.caMinimumDurationInDays = caMinimumDurationInDays;
    this.leafMinimumDurationInDays = leafMinimumDurationInDays;
  }

  @Override
  public CertificateCredentialValue generateCredential(final GenerationParameters p) {
    final CertificateGenerationParameters params = (CertificateGenerationParameters) p;
    final KeyPair keyPair;
    final String privatePem;
    try {
      keyPair = keyGenerator.generateKeyPair(params.getKeyLength());
      privatePem = CertificateFormatter.pemOf(keyPair.getPrivate());
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }

    final int originalDuration = params.getDuration();

    params.setDuration(getCertificateDuration(params));

    final boolean durationOverridden = originalDuration != params.getDuration();

    if (params.isSelfSigned()) {
      try {
        final String cert = CertificateFormatter.pemOf(signedCertificateGenerator.getSelfSigned(keyPair, params));
        return new CertificateCredentialValue(cert, cert, privatePem, null, null, params.isCa(), params.isSelfSigned(), true, false, durationOverridden, params.getDuration());
      } catch (final Exception e) {
        throw new RuntimeException(e);
      }
    } else {
      final String caName = params.getCaName();
      final CertificateCredentialValue latestNonTransitionalCaVersion = certificateAuthorityService.findActiveVersion(caName);
      if (latestNonTransitionalCaVersion.getPrivateKey() == null) {
        throw new ParameterizedValidationException(ErrorMessages.CA_MISSING_PRIVATE_KEY);
      }
      final CertificateCredentialValue transitionalCaVersion = certificateAuthorityService.findTransitionalVersion(caName);

      String signingCaCertificate;
      String signingCaPrivateKey;
      String trustedCaCertificate = null;

      if (shouldUseTransitionalParentToSign(params.getAllowTransitionalParentToSign(), latestNonTransitionalCaVersion, transitionalCaVersion)) {
        signingCaCertificate = transitionalCaVersion.getCertificate();
        signingCaPrivateKey = transitionalCaVersion.getPrivateKey();
        trustedCaCertificate = latestNonTransitionalCaVersion.getCertificate();
      } else {
        signingCaCertificate = latestNonTransitionalCaVersion.getCertificate();
        signingCaPrivateKey = latestNonTransitionalCaVersion.getPrivateKey();
        if (transitionalCaVersion != null) {
          trustedCaCertificate = transitionalCaVersion.getCertificate();
        }
      }

      try {

        final CertificateReader certificateReader = new CertificateReader(signingCaCertificate);

        final X509Certificate cert = signedCertificateGenerator.getSignedByIssuer(
          keyPair,
          params,
          certificateReader.getCertificate(),
          PrivateKeyReader.getPrivateKey(signingCaPrivateKey)
        );
        return new CertificateCredentialValue(signingCaCertificate, CertificateFormatter.pemOf(cert), privatePem, caName, trustedCaCertificate, params.isCa(), params.isSelfSigned(), true, false, durationOverridden, params.getDuration());
      } catch (final Exception e) {
        throw new RuntimeException(e);
      }
    }
  }

  private boolean shouldUseTransitionalParentToSign(final Boolean allowTransitionalParentToSign, final CertificateCredentialValue latestNonTransitionalCaVersion, final CertificateCredentialValue transitionalCaVersion) {
    if (!allowTransitionalParentToSign) {
      return false;
    }

    if (transitionalCaVersion == null) {
      return false;
    }

    final Instant transitionalVersionCreatedAt = transitionalCaVersion.getVersionCreatedAt();
    final Instant latestNonTransitionalVersionCreatedAt = latestNonTransitionalCaVersion.getVersionCreatedAt();
    if (transitionalVersionCreatedAt == null || latestNonTransitionalVersionCreatedAt == null) {
      return false;
    }

    return transitionalVersionCreatedAt.isAfter(latestNonTransitionalVersionCreatedAt);
  }

  private int getCertificateDuration(final CertificateGenerationParameters params) {
    if (params.isCa()) {
      return Math.max(params.getDuration(), caMinimumDurationInDays);
    }
    return Math.max(params.getDuration(), leafMinimumDurationInDays);
  }
}
