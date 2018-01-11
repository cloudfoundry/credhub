package org.cloudfoundry.credhub.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.stereotype.Component;

@Component
@EnableAsync
@Profile({"prod", "dev"})
class AsyncEncryptionKeyRotationScheduler {

  private EncryptionKeyRotator encryptionKeyRotator;

  @Autowired
  public AsyncEncryptionKeyRotationScheduler(
      EncryptionKeyRotator encryptionKeyRotator,
      DecryptableDataDetector decryptableDataDetector
  ) {
    this.encryptionKeyRotator = encryptionKeyRotator;

    decryptableDataDetector.check();
  }

  @Async
  @EventListener(ContextRefreshedEvent.class)
  public void rotate() {
    encryptionKeyRotator.rotate();
  }
}
