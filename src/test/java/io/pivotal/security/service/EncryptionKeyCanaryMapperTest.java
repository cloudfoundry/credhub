package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.data.EncryptionKeyCanaryDataService;
import io.pivotal.security.entity.EncryptionKeyCanary;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.service.EncryptionKeyCanaryMapper.CANARY_VALUE;
import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class EncryptionKeyCanaryMapperTest {
  private EncryptionKeyCanaryMapper subject;
  private EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;
  private EncryptionService encryptionService;
  private UUID activeCanaryUUID;
  private UUID existingCanaryUUID1;
  private UUID existingCanaryUUID2;
  private EncryptionKey activeEncryptionKey;
  private EncryptionKey existingEncryptionKey1;
  private EncryptionKey existingEncryptionKey2;
  private EncryptionKeyCanary activeEncryptionKeyCanary;
  private EncryptionKeyCanary existingEncryptionKeyCanary1;
  private EncryptionKeyCanary existingEncryptionKeyCanary2;

  {
    beforeEach(() -> {
      encryptionKeyCanaryDataService = mock(EncryptionKeyCanaryDataService.class);
      encryptionService = mock(EncryptionService.class);

      activeCanaryUUID = UUID.randomUUID();

      activeEncryptionKey = mock(EncryptionKey.class);
      when(encryptionService.getActiveKey()).thenReturn(activeEncryptionKey);

      activeEncryptionKeyCanary = createEncryptionCanary(activeCanaryUUID, "fake-active-encrypted-value", "fake-active-nonce", activeEncryptionKey);

      when(activeEncryptionKey.encrypt(CANARY_VALUE))
          .thenReturn(new Encryption("fake-encrypted-value".getBytes(), "fake-nonce".getBytes()));
    });

    describe("when the active key is the only key", () -> {
      beforeEach(() -> {
        when(encryptionService.getKeys()).thenReturn(asList(activeEncryptionKey));
      });

      describe("when there are no canaries in the database", () -> {
        beforeEach(() -> {
          when(encryptionKeyCanaryDataService.findAll()).thenReturn(new ArrayList<>());

          when(encryptionKeyCanaryDataService.save(any(EncryptionKeyCanary.class)))
              .thenReturn(activeEncryptionKeyCanary);

          subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService, encryptionService);
        });

        it("creates and saves canary to the database", () -> {
          ArgumentCaptor<EncryptionKeyCanary> argumentCaptor = ArgumentCaptor.forClass(EncryptionKeyCanary.class);
          verify(encryptionKeyCanaryDataService, times(1)).save(argumentCaptor.capture());

          EncryptionKeyCanary encryptionKeyCanary = argumentCaptor.getValue();
          assertThat(encryptionKeyCanary.getEncryptedValue(), equalTo("fake-encrypted-value".getBytes()));
          assertThat(encryptionKeyCanary.getNonce(), equalTo("fake-nonce".getBytes()));
          verify(activeEncryptionKey, times(1)).encrypt(CANARY_VALUE);
        });

        it("returns a map between the new canary and the active key", () -> {
          Map<UUID, EncryptionKey> encryptionKeyMap = subject.getEncryptionKeyMap();

          assertThat(encryptionKeyMap.entrySet().size(), equalTo(1));
          assertThat(encryptionKeyMap.get(activeCanaryUUID), equalTo(activeEncryptionKey));
        });

        it("sets the new canary's UUID as active", () -> {
          assertThat(subject.getActiveUuid(), equalTo(activeCanaryUUID));
        });
      });

      describe("when there is no matching canary in the database", () -> {
        beforeEach(() -> {
          EncryptionKeyCanary nonMatchingCanary = new EncryptionKeyCanary();
          nonMatchingCanary.setUuid(UUID.randomUUID());
          nonMatchingCanary.setEncryptedValue("fake-non-matching-encrypted-value".getBytes());
          nonMatchingCanary.setNonce("fake-non-matching-nonce".getBytes());

          when(encryptionKeyCanaryDataService.findAll()).thenReturn(Arrays.asList(nonMatchingCanary));
          when(activeEncryptionKey.decrypt(nonMatchingCanary.getEncryptedValue(), nonMatchingCanary.getNonce()))
              .thenReturn("different-canary-value");
          when(encryptionKeyCanaryDataService.save(any(EncryptionKeyCanary.class)))
              .thenReturn(activeEncryptionKeyCanary);

          subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService, encryptionService);
        });

        it("should create a canary for the key", () -> {
          ArgumentCaptor<EncryptionKeyCanary> argumentCaptor = ArgumentCaptor.forClass(EncryptionKeyCanary.class);
          verify(encryptionKeyCanaryDataService, times(1)).save(argumentCaptor.capture());

          EncryptionKeyCanary encryptionKeyCanary = argumentCaptor.getValue();
          assertThat(encryptionKeyCanary.getEncryptedValue(), equalTo("fake-encrypted-value".getBytes()));
          assertThat(encryptionKeyCanary.getNonce(), equalTo("fake-nonce".getBytes()));
          verify(activeEncryptionKey, times(1)).encrypt(CANARY_VALUE);
        });
      });

      describe("when there is a matching canary in the database", () -> {
        beforeEach(() -> {
          when(encryptionKeyCanaryDataService.findAll()).thenReturn(asList(activeEncryptionKeyCanary));
          when(activeEncryptionKey.decrypt(activeEncryptionKeyCanary.getEncryptedValue(), activeEncryptionKeyCanary.getNonce()))
              .thenReturn(CANARY_VALUE);

          subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService, encryptionService);
        });

        it("should map the key to the matching canary", () -> {
          Map<UUID, EncryptionKey> encryptionKeyMap = subject.getEncryptionKeyMap();

          assertThat(encryptionKeyMap.entrySet().size(), equalTo(1));
          assertThat(encryptionKeyMap.get(activeCanaryUUID), equalTo(activeEncryptionKey));
        });

        it("should not re-encrypt the canary value", () -> {
          verify(activeEncryptionKey, times(0)).encrypt(any(String.class));
        });

        it("sets the matching canary's UUID as active", () -> {
          assertThat(subject.getActiveUuid(), equalTo(activeCanaryUUID));
        });
      });
    });

    describe("when there are multiple keys", () -> {
      beforeEach(() -> {
        existingCanaryUUID1 = UUID.randomUUID();
        existingCanaryUUID2 = UUID.randomUUID();

        existingEncryptionKey1 = mock(EncryptionKey.class);
        existingEncryptionKey2 = mock(EncryptionKey.class);

        when(encryptionService.getKeys()).thenReturn(asList(existingEncryptionKey1, activeEncryptionKey, existingEncryptionKey2));

        existingEncryptionKeyCanary1 = new EncryptionKeyCanary();
        existingEncryptionKeyCanary1.setUuid(existingCanaryUUID1);
        existingEncryptionKeyCanary1.setEncryptedValue("fake-existing-encrypted-value1".getBytes());
        existingEncryptionKeyCanary1.setNonce("fake-existing-nonce1".getBytes());
        when(existingEncryptionKey1.decrypt("fake-existing-encrypted-value1".getBytes(), "fake-existing-nonce1".getBytes()))
            .thenReturn(CANARY_VALUE);
        
        existingEncryptionKeyCanary2 = new EncryptionKeyCanary();
        existingEncryptionKeyCanary2.setUuid(existingCanaryUUID2);
        existingEncryptionKeyCanary2.setEncryptedValue("fake-existing-encrypted-value2".getBytes());
        existingEncryptionKeyCanary2.setNonce("fake-existing-nonce2".getBytes());
        when(existingEncryptionKey2.decrypt("fake-existing-encrypted-value2".getBytes(), "fake-existing-nonce2".getBytes()))
            .thenReturn(CANARY_VALUE);
      });

      describe("when there are matching canaries for all of the keys", () -> {
        beforeEach(() -> {
          when(encryptionKeyCanaryDataService.findAll()).thenReturn(asList(existingEncryptionKeyCanary1, activeEncryptionKeyCanary, existingEncryptionKeyCanary2));

          subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService, encryptionService);
        });

        it("should return a map between the matching canaries and keys", () -> {
          Map<UUID, EncryptionKey> encryptionKeyMap = subject.getEncryptionKeyMap();

          assertThat(encryptionKeyMap.entrySet().size(), equalTo(3));
          assertThat(encryptionKeyMap.get(activeCanaryUUID), equalTo(activeEncryptionKey));
          assertThat(encryptionKeyMap.get(existingCanaryUUID1), equalTo(existingEncryptionKey1));
          assertThat(encryptionKeyMap.get(existingCanaryUUID2), equalTo(existingEncryptionKey2));
        });

        it("should set the active key's canary UUID as active", () -> {
          assertThat(subject.getActiveUuid(), equalTo(activeCanaryUUID));
        });
      });

      describe("when there is a non-active key that does not have a matching canary", () -> {
        beforeEach(() -> {
          when(encryptionKeyCanaryDataService.findAll()).thenReturn(asList(existingEncryptionKeyCanary1, activeEncryptionKeyCanary));

          subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService, encryptionService);
        });

        it("should not create a canary for the key", () -> {
          verify(encryptionKeyCanaryDataService, times(0)).save(any(EncryptionKeyCanary.class));
        });

        it("should not include it in the returned map", () -> {
          Map<UUID, EncryptionKey> encryptionKeyMap = subject.getEncryptionKeyMap();

          assertThat(encryptionKeyMap.entrySet().size(), equalTo(2));
          assertThat(encryptionKeyMap.get(activeCanaryUUID), equalTo(activeEncryptionKey));
          assertThat(encryptionKeyMap.get(existingCanaryUUID1), equalTo(existingEncryptionKey1));
        });

        it("should set the active key's canary UUID as active", () -> {
          assertThat(subject.getActiveUuid(), equalTo(activeCanaryUUID));
        });
      });
    });
  }

  private EncryptionKeyCanary createEncryptionCanary(UUID activeCanaryUUID, String encryptedValue, String nonce, EncryptionKey encryptionKey)
      throws Exception {
    EncryptionKeyCanary encryptionKeyCanary = new EncryptionKeyCanary();
    encryptionKeyCanary.setUuid(activeCanaryUUID);
    encryptionKeyCanary.setEncryptedValue(encryptedValue.getBytes());
    encryptionKeyCanary.setNonce(nonce.getBytes());
    when(encryptionKey.decrypt(encryptedValue.getBytes(), nonce.getBytes()))
        .thenReturn(CANARY_VALUE);
    return encryptionKeyCanary;
  }
}
