package io.pivotal.security.helper;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.util.CurrentTimeProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.Security;
import java.time.Instant;
import java.util.Calendar;
import java.util.Objects;
import java.util.TimeZone;
import java.util.function.Consumer;

import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;

public class SpectrumHelper {

  public static <T extends Throwable> void itThrows(final String behavior,
                                                    final Class<T> throwableClass, final Spectrum.Block block) {
    Spectrum.it(behavior, () -> {
      try {
        block.run();
        fail("Expected " + throwableClass.getSimpleName() + " to be thrown, but it wasn't");
      } catch (Throwable t) {
        if (!throwableClass.isAssignableFrom(t.getClass())) {
          t.printStackTrace();

          fail("Expected " + throwableClass.getSimpleName() + " to be thrown, but got " + t
              .getClass().getSimpleName());
        }
      }
    });
  }

  public static <T extends Throwable> void itThrowsWithMessage(final String behavior,
                                                               final Class<T> throwableClass, final String message, final Spectrum.Block block) {
    Spectrum.it(behavior, () -> {
      try {
        block.run();
        fail("Expected " + throwableClass.getSimpleName() + " to be thrown, but it wasn't");
      } catch (Throwable t) {
        if (!(throwableClass.isAssignableFrom(t.getClass()) && Objects.equals(message, t.getMessage()))) {
          t.printStackTrace();

          fail("Expected " + throwableClass.getSimpleName() + " with message " + message
              + " to be thrown, but got " + t.getClass().getSimpleName() + " with message " + t
              .getMessage());
        }
      }
    });
  }

  public static String json(Object o) throws IOException {
    return new ObjectMapper().writeValueAsString(o);
  }

  public static Consumer<Long> mockOutCurrentTimeProvider(
      CurrentTimeProvider mockCurrentTimeProvider) {
    return (epochMillis) -> {
      when(mockCurrentTimeProvider.getNow()).thenReturn(getNow(epochMillis));
      when(mockCurrentTimeProvider.getInstant()).thenReturn(Instant.ofEpochMilli(epochMillis));
    };
  }

  private static Calendar getNow(long epochMillis) {
    Calendar.Builder builder = new Calendar.Builder();
    builder.setInstant(epochMillis);
    builder.setTimeZone(TimeZone.getTimeZone("UTC"));
    return builder.build();
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
