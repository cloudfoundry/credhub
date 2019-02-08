package org.cloudfoundry.credhub.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.stereotype.Component;

@Component
@EnableAsync
@Profile({
  "prod",
  "dev",
})
public class AsyncEncryptionKeyRotationScheduler {

  private final EncryptionKeyRotator encryptionKeyRotator;

  @Autowired
  public AsyncEncryptionKeyRotationScheduler(
    final EncryptionKeyRotator encryptionKeyRotator,
    final DecryptableDataDetector decryptableDataDetector
  ) {
    super();
    this.encryptionKeyRotator = encryptionKeyRotator;

    decryptableDataDetector.check();
  }

  @Async
  @EventListener(ContextRefreshedEvent.class)
  public void rotate() {
    encryptionKeyRotator.rotate();
  }
}
