package org.cloudfoundry.credhub.helper;

import java.security.Security;
import java.time.Instant;
import java.util.Optional;
import java.util.function.Consumer;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;

import static org.mockito.Mockito.when;

final public class TestHelper {

  private TestHelper() {
  }

  public static Consumer<Long> mockOutCurrentTimeProvider(
    CurrentTimeProvider mockCurrentTimeProvider) {
    return (epochMillis) -> {
      when(mockCurrentTimeProvider.getNow()).thenReturn(Optional.of(Instant.ofEpochMilli(epochMillis)));
      when(mockCurrentTimeProvider.getInstant()).thenReturn(Instant.ofEpochMilli(epochMillis));
    };
  }

  public static BouncyCastleProvider getBouncyCastleProvider() {
    BouncyCastleProvider bouncyCastleProvider = (BouncyCastleProvider) Security
      .getProvider(BouncyCastleProvider.PROVIDER_NAME);

    if (bouncyCastleProvider == null) {
      bouncyCastleProvider = new BouncyCastleProvider();
      Security.addProvider(bouncyCastleProvider);
    }

    return bouncyCastleProvider;
  }
}
