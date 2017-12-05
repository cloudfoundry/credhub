package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.data.CredentialVersionDataService;
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
  private CredentialVersionDataService credentialVersionDataService;

  @Autowired
  public AsyncEncryptionKeyRotationScheduler(
      EncryptionKeyRotator encryptionKeyRotator,
      EncryptionKeyCanaryMapper encryptionKeyCanaryMapper,
      CredentialVersionDataService credentialVersionDataService
  ) {
    this.encryptionKeyRotator = encryptionKeyRotator;
    this.encryptionKeyCanaryMapper = encryptionKeyCanaryMapper;
    this.credentialVersionDataService = credentialVersionDataService;

    makeSureWeCanDecryptSomething();
  }

  public void makeSureWeCanDecryptSomething() {
    (new DecryptableDataDetector(encryptionKeyCanaryMapper, credentialVersionDataService)).check();
  }

  @Async
  @EventListener(ContextRefreshedEvent.class)
  public void rotate() {
    encryptionKeyRotator.rotate();
  }
}
