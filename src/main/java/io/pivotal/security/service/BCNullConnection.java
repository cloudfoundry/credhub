package io.pivotal.security.service;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@SuppressWarnings("unused")
@Component
@ConditionalOnProperty(value = "encryption.provider", havingValue = "dev_internal")
public class BCNullConnection implements RemoteEncryptionConnectable {
  @Override
  public void reconnect(Exception originalException) throws Exception{
    if (originalException == null) {
      return;
    }
    throw originalException;
  }
}
