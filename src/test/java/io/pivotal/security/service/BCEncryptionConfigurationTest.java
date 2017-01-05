package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.config.DevKeyProvider;
import io.pivotal.security.config.EncryptionKeysConfiguration;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.stream.Collectors;

import javax.xml.bind.DatatypeConverter;

@RunWith(Spectrum.class)
public class BCEncryptionConfigurationTest {
  private BCEncryptionConfiguration subject;

  {
    beforeEach(() -> {
      DevKeyProvider devKeyProvider = mock(DevKeyProvider.class);
      when(devKeyProvider.getDevKey()).thenReturn("0123456789ABCDEF0123456789ABCDEF");

      EncryptionKeysConfiguration encryptionKeysConfiguration = mock(EncryptionKeysConfiguration.class);
      when(encryptionKeysConfiguration.getKeys()).thenReturn(asList("0123456789ABCDEF0123456789ABCDEF", "5555556789ABCDEF0123456789ABCDEF"));
      subject = new BCEncryptionConfiguration(new BouncyCastleProvider(), devKeyProvider, encryptionKeysConfiguration);
    });

    describe("#getActiveKey", () -> {
      it("should use the correct algorithm", () -> {
        assertThat(subject.getActiveKey().getKey().getAlgorithm(), equalTo("AES"));
      });

      it("should use key of length 128 bits", () -> {
        assertThat(subject.getActiveKey().getKey().getEncoded().length, equalTo(16));
      });

      it("should create a key using the provided dev key value", () -> {
        assertThat(DatatypeConverter.printHexBinary(subject.getActiveKey().getKey().getEncoded()), equalTo("0123456789ABCDEF0123456789ABCDEF"));
      });
    });

    describe("#getKeys", () -> {
      it("should return the keys", () -> {
        List<String> plaintextKeys = subject.getKeys().stream().map(key -> DatatypeConverter.printHexBinary(key.getKey().getEncoded())).collect(Collectors.toList());
        assertThat(plaintextKeys, containsInAnyOrder("0123456789ABCDEF0123456789ABCDEF", "5555556789ABCDEF0123456789ABCDEF"));
      });
    });
  }
}
