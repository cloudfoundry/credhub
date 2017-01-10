package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.Key;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RunWith(Spectrum.class)
public class EncryptionKeyServiceTest {
  private EncryptionKeyService subject;

  private Key activeEncryptionKey;

  private UUID activeEncryptionKeyUuid;

  private Key anotherEncryptionKey;

  private UUID anotherEncryptionKeyUuid;

  {
    beforeEach(() -> {
      EncryptionKeyCanaryMapper encryptionKeyCanaryMapper = mock(EncryptionKeyCanaryMapper.class);
      activeEncryptionKey = mock(Key.class);
      activeEncryptionKeyUuid = UUID.randomUUID();

      anotherEncryptionKey = mock(Key.class);
      anotherEncryptionKeyUuid = UUID.randomUUID();

      Map<UUID, Key> encryptionKeys = new HashMap<>();
      encryptionKeys.put(activeEncryptionKeyUuid, activeEncryptionKey);
      encryptionKeys.put(anotherEncryptionKeyUuid, anotherEncryptionKey);

      when(encryptionKeyCanaryMapper.getActiveUuid()).thenReturn(activeEncryptionKeyUuid);
      when(encryptionKeyCanaryMapper.getEncryptionKeyMap()).thenReturn(encryptionKeys);

      subject = new EncryptionKeyService(encryptionKeyCanaryMapper);
    });

    describe("#getEncryptionKey", () -> {
      describe("when the key exists in the encryption key map", () -> {
        it("should return the key", () -> {
          assertThat(subject.getEncryptionKey(activeEncryptionKeyUuid), equalTo(activeEncryptionKey));
          assertThat(subject.getEncryptionKey(anotherEncryptionKeyUuid), equalTo(anotherEncryptionKey));
        });
      });

      describe("when the key is not in the map", () -> {
        it("should return null", () -> {
          assertThat(subject.getEncryptionKey(UUID.randomUUID()), equalTo(null));
        });
      });
    });

    describe("#getActiveEncryptionKeyUuid", () -> {
      it("should return the active key's UUID", () -> {
        assertThat(subject.getActiveEncryptionKeyUuid(), equalTo(activeEncryptionKeyUuid));
      });
    });

    describe("#getActiveEncryptionKey", () -> {
      it("should return the active key", () -> {
        assertThat(subject.getActiveEncryptionKey(), equalTo(activeEncryptionKey));
      });
    });
  }
}
