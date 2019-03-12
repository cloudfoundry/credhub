package org.cloudfoundry.credhub;

import java.security.Security;
import java.time.Instant;
import java.util.Optional;
import java.util.function.Consumer;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;

import static org.mockito.Mockito.when;

final public class TestHelper {

  private TestHelper() {
    super();
  }

  public static Consumer<Long> mockOutCurrentTimeProvider(
    final CurrentTimeProvider mockCurrentTimeProvider) {
    return (epochMillis) -> {
      when(mockCurrentTimeProvider.getNow()).thenReturn(Optional.of(Instant.ofEpochMilli(epochMillis)));
      when(mockCurrentTimeProvider.getInstant()).thenReturn(Instant.ofEpochMilli(epochMillis));
    };
  }

  public static BouncyCastleFipsProvider getBouncyCastleFipsProvider() {
    BouncyCastleFipsProvider bouncyCastleFipsProvider = (BouncyCastleFipsProvider) Security
      .getProvider(BouncyCastleFipsProvider.PROVIDER_NAME);

    if (bouncyCastleFipsProvider == null) {
      bouncyCastleFipsProvider = new BouncyCastleFipsProvider();
      Security.addProvider(bouncyCastleFipsProvider);
    }

    return bouncyCastleFipsProvider;
  }
}
