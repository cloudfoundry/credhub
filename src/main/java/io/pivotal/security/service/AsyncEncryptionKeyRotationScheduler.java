package io.pivotal.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.stereotype.Component;

@Component
@EnableAsync
@Profile({"default", "dev"})
class AsyncEncryptionKeyRotationScheduler {
  EncryptionKeyRotator encryptionKeyRotator;

  @Autowired
  public AsyncEncryptionKeyRotationScheduler(EncryptionKeyRotator encryptionKeyRotator) {
    this.encryptionKeyRotator = encryptionKeyRotator;
  }

  @Async
  @EventListener(ContextRefreshedEvent.class)
  public void rotate() {
    encryptionKeyRotator.rotate();
  }
}
