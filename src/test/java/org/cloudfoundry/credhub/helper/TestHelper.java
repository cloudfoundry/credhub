package org.cloudfoundry.credhub.helper;

import org.cloudfoundry.credhub.util.CurrentTimeProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.time.Instant;
import java.util.Calendar;
import java.util.Optional;
import java.util.TimeZone;
import java.util.function.Consumer;

import static org.mockito.Mockito.when;

public class TestHelper {


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
