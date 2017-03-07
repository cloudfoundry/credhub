package io.pivotal.security.service;

import io.pivotal.security.data.SecretDataService;
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
  private EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;
  private SecretDataService secretDataService;

  @Autowired
  public AsyncEncryptionKeyRotationScheduler(
    EncryptionKeyRotator encryptionKeyRotator,
    EncryptionKeyCanaryMapper encryptionKeyCanaryMapper,
    SecretDataService secretDataService
  ) {
    this.encryptionKeyRotator = encryptionKeyRotator;
    this.encryptionKeyCanaryMapper = encryptionKeyCanaryMapper;
    this.secretDataService = secretDataService;

    makeSureWeCanDecryptSomething();
  }

  public void makeSureWeCanDecryptSomething() {
    (new DecryptableDataDetector(encryptionKeyCanaryMapper, secretDataService)).check();
  }

  @Async
  @EventListener(ContextRefreshedEvent.class)
  public void rotate() {
    encryptionKeyRotator.rotate();
  }
}
