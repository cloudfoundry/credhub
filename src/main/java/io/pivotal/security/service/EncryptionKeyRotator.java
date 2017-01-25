package io.pivotal.security.service;

import io.pivotal.security.data.CertificateAuthorityDataService;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.SecretEncryptionHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.data.domain.Slice;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.stereotype.Component;

@Component
@EnableAsync
class EncryptionKeyRotator {
  private final SecretEncryptionHelper secretEncryptionHelper;
  private final SecretDataService secretDataService;
  private final CertificateAuthorityDataService certificateAuthorityDataService;
  private final Logger logger;

  EncryptionKeyRotator(
      SecretEncryptionHelper secretEncryptionHelper,
      SecretDataService secretDataService,
      CertificateAuthorityDataService certificateAuthorityDataService
  ) {
    this.secretEncryptionHelper = secretEncryptionHelper;
    this.secretDataService = secretDataService;
    this.certificateAuthorityDataService = certificateAuthorityDataService;
    this.logger = LogManager.getLogger(this.getClass());
  }

  @Async
  @EventListener(ContextRefreshedEvent.class)
  public void rotate() {
    final long start = System.currentTimeMillis();
    logger.info("Started encryption key rotation");
    final int[] count = {0};

    Slice<NamedSecret> secretsEncryptedByOldKey = secretDataService.findNotEncryptedByActiveKey();
    while (secretsEncryptedByOldKey.hasContent()) {
      secretsEncryptedByOldKey.getContent().forEach(secret -> {
        secretEncryptionHelper.rotate(secret);
        secretDataService.save(secret);
        count[0]++;
      });
      secretsEncryptedByOldKey = secretDataService.findNotEncryptedByActiveKey();
    }

    Slice<NamedCertificateAuthority> certificateAuthoritiesEncryptedByOldKey = certificateAuthorityDataService.findNotEncryptedByActiveKey();
    while (certificateAuthoritiesEncryptedByOldKey.hasContent()) {
      certificateAuthoritiesEncryptedByOldKey.getContent().forEach(certificateAuthority -> {
        secretEncryptionHelper.rotate(certificateAuthority);
        certificateAuthorityDataService.save(certificateAuthority);
        count[0]++;
      });
      certificateAuthoritiesEncryptedByOldKey = certificateAuthorityDataService.findNotEncryptedByActiveKey();
    }

    final long finish = System.currentTimeMillis();
    final long delta = finish - start;
    logger.info("Finished encryption key rotation of " + count[0] + " item(s) - took " + delta + " milliseconds.");
  }
}
