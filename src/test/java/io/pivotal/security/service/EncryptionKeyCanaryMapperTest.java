package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.config.EncryptionKeysConfiguration;
import io.pivotal.security.data.EncryptionKeyCanaryDataService;
import io.pivotal.security.entity.EncryptionKeyCanary;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static io.pivotal.security.service.EncryptionKeyCanaryMapper.CANARY_VALUE;
import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.Key;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

@RunWith(Spectrum.class)
public class EncryptionKeyCanaryMapperTest {
  private EncryptionKeyCanaryMapper subject;
  private EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;
  private EncryptionService encryptionService;
  private UUID activeCanaryUUID;
  private UUID existingCanaryUUID1;
  private UUID existingCanaryUUID2;
  private Key activeKey;
  private Key existingKey1;
  private Key existingKey2;
  private EncryptionKeyMetadata activeKeyData;
  private EncryptionKeyMetadata existingKey1Data;
  private EncryptionKeyMetadata existingKey2Data;
  private EncryptionKeyCanary activeEncryptionKeyCanary;
  private EncryptionKeyCanary existingEncryptionKeyCanary1;
  private EncryptionKeyCanary existingEncryptionKeyCanary2;

  private EncryptionKeysConfiguration encryptionKeysConfiguration;

  {
    beforeEach(() -> {
      encryptionKeyCanaryDataService = mock(EncryptionKeyCanaryDataService.class);
      encryptionService = mock(EncryptionService.class);
      encryptionKeysConfiguration = mock(EncryptionKeysConfiguration.class);

      activeCanaryUUID = UUID.randomUUID();
      existingCanaryUUID1 = UUID.randomUUID();
      existingCanaryUUID2 = UUID.randomUUID();

      activeKeyData = new EncryptionKeyMetadata("activeDevKey", "activeDevKeyName", true);
      existingKey1Data = new EncryptionKeyMetadata("key1", "key1Name", false);
      existingKey2Data = new EncryptionKeyMetadata("key2", "key2Name", false);
      activeKey = mock(Key.class, "active key");
      existingKey1 = mock(Key.class, "key 1");
      existingKey2 = mock(Key.class, "key 2");

      activeEncryptionKeyCanary = createEncryptionCanary(activeCanaryUUID, "fake-active-encrypted-value", "fake-active-nonce", activeKey);
      existingEncryptionKeyCanary1 = createEncryptionCanary(existingCanaryUUID1, "fake-existing-encrypted-value1", "fake-existing-nonce1", existingKey1);
      existingEncryptionKeyCanary2 = createEncryptionCanary(existingCanaryUUID2, "fake-existing-encrypted-value2", "fake-existing-nonce2", existingKey2);

      when(encryptionService.encrypt(activeKey, CANARY_VALUE))
          .thenReturn(new Encryption("fake-encrypted-value".getBytes(), "fake-nonce".getBytes()));
      when(encryptionKeysConfiguration.getKeys()).thenReturn(newArrayList(
          existingKey1Data,
          activeKeyData,
          existingKey2Data
      ));
      when(encryptionService.createKey(eq(activeKeyData))).thenReturn(activeKey);
      when(encryptionService.createKey(eq(existingKey1Data))).thenReturn(existingKey1);
      when(encryptionService.createKey(eq(existingKey2Data))).thenReturn(existingKey2);

      when(encryptionKeyCanaryDataService.findAll()).thenReturn(asList(existingEncryptionKeyCanary1, activeEncryptionKeyCanary, existingEncryptionKeyCanary2));

      subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService, encryptionKeysConfiguration);
      subject.mapUuidsToKeys(encryptionService);
    });

    describe("#mapCanariesToKeys", () -> {
      it("should create the keys", () -> {
        final List<Key> keys = subject.getKeys();
        assertThat(keys.size(), equalTo(3));
        assertThat(keys, containsInAnyOrder(
            activeKey, existingKey1, existingKey2
        ));
      });

      it("should contain a reference to the active key", () -> {
        assertThat(subject.getKeys(), hasItem(subject.getActiveKey()));
      });
    });

    describe("when there is no active key", () -> {
      beforeEach(() -> {
        when(encryptionKeysConfiguration.getKeys()).thenReturn(asList());
      });

      itThrowsWithMessage("a warning about no active key", RuntimeException.class, "No active key was found", () -> {
        subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService, encryptionKeysConfiguration);
        subject.mapUuidsToKeys(encryptionService);
      });
    });

    describe("when the active key is the only key", () -> {
      beforeEach(() -> {
        when(encryptionKeysConfiguration.getKeys()).thenReturn(asList(activeKeyData));
      });

      describe("when there are no canaries in the database", () -> {
        beforeEach(() -> {
          when(encryptionKeyCanaryDataService.findAll()).thenReturn(new ArrayList<>());

          when(encryptionKeyCanaryDataService.save(any(EncryptionKeyCanary.class)))
              .thenReturn(activeEncryptionKeyCanary);

          subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService, encryptionKeysConfiguration);
          subject.mapUuidsToKeys(encryptionService);
        });

        it("creates and saves a canary to the database", () -> {
          assertCanaryValueWasEncryptedAndSavedToDatabase();
        });

        it("maps between the new canary and the active key", () -> {
          assertThat(subject.getKeyForUuid(activeCanaryUUID), equalTo(activeKey));
          assertThat(subject.getUuidForKey(activeKey), equalTo(activeCanaryUUID));
        });

        it("sets the new canary's UUID as active", () -> {
          assertThat(subject.getActiveUuid(), equalTo(activeCanaryUUID));
        });
      });

      describe("when there is no matching canary in the database", () -> {
        EncryptionKeyCanary nonMatchingCanary = new EncryptionKeyCanary();

        beforeEach(() -> {
          nonMatchingCanary.setUuid(UUID.randomUUID());
          nonMatchingCanary.setEncryptedValue("fake-non-matching-encrypted-value".getBytes());
          nonMatchingCanary.setNonce("fake-non-matching-nonce".getBytes());

          when(encryptionKeyCanaryDataService.findAll()).thenReturn(Arrays.asList(nonMatchingCanary));
        });

        describe("when decrypting with the wrong key raises AEADBadTagException -- dev_internal", () -> {
          beforeEach(() -> {
            when(encryptionService.decrypt(activeKey, nonMatchingCanary.getEncryptedValue(), nonMatchingCanary.getNonce()))
                .thenThrow(new AEADBadTagException());
            when(encryptionKeyCanaryDataService.save(any(EncryptionKeyCanary.class)))
                .thenReturn(activeEncryptionKeyCanary);

            subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService, encryptionKeysConfiguration);
            subject.mapUuidsToKeys(encryptionService);
          });

          it("should create a canary for the key", () -> {
            assertCanaryValueWasEncryptedAndSavedToDatabase();
          });
        });

        describe("when decrypting with the wrong key raises a known IllegalBlockSizeException error -- HSM", () -> {
          beforeEach(() -> {
            when(encryptionService.decrypt(activeKey, nonMatchingCanary.getEncryptedValue(), nonMatchingCanary.getNonce()))
                .thenThrow(new IllegalBlockSizeException("Could not process input data: function 'C_Decrypt' returns 0x40"));
            when(encryptionKeyCanaryDataService.save(any(EncryptionKeyCanary.class)))
                .thenReturn(activeEncryptionKeyCanary);

            subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService, encryptionKeysConfiguration);
            subject.mapUuidsToKeys(encryptionService);
          });

          it("should create a canary for the key", () -> {
            assertCanaryValueWasEncryptedAndSavedToDatabase();
          });
        });

        describe("when decrypting with the wrong key raises an unknown IllegalBlockSizeException error -- HSM", () -> {
          beforeEach(() -> {
            when(encryptionService.decrypt(activeKey, nonMatchingCanary.getEncryptedValue(), nonMatchingCanary.getNonce()))
                .thenThrow(new IllegalBlockSizeException("I don't know what 0x41 means and neither do you"));
            when(encryptionKeyCanaryDataService.save(any(EncryptionKeyCanary.class)))
                .thenReturn(activeEncryptionKeyCanary);
          });

          itThrowsWithMessage("something", RuntimeException.class, "javax.crypto.IllegalBlockSizeException: I don't know what 0x41 means and neither do you", () -> {
            subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService, encryptionKeysConfiguration);
            subject.mapUuidsToKeys(encryptionService);
          });
        });

        describe("when decrypting with the wrong key raises a known BadPaddingException error -- DSM", () -> {
          beforeEach(() -> {
            when(encryptionService.decrypt(activeKey, nonMatchingCanary.getEncryptedValue(), nonMatchingCanary.getNonce()))
                .thenThrow(new BadPaddingException("Decrypt error: rv=48"));
            when(encryptionKeyCanaryDataService.save(any(EncryptionKeyCanary.class)))
                .thenReturn(activeEncryptionKeyCanary);

            subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService, encryptionKeysConfiguration);
            subject.mapUuidsToKeys(encryptionService);
          });

          it("should create a canary for the key", () -> {
            assertCanaryValueWasEncryptedAndSavedToDatabase();
          });
        });

        describe("when decrypting with the wrong key raises an unknown BadPaddingException error -- DSM", () -> {
          beforeEach(() -> {
            when(encryptionService.decrypt(activeKey, nonMatchingCanary.getEncryptedValue(), nonMatchingCanary.getNonce()))
                .thenThrow(new BadPaddingException("Decrypt error: rv=1337 too cool for school"));
            when(encryptionKeyCanaryDataService.save(any(EncryptionKeyCanary.class)))
                .thenReturn(activeEncryptionKeyCanary);
          });

          itThrowsWithMessage("something", RuntimeException.class, "javax.crypto.BadPaddingException: Decrypt error: rv=1337 too cool for school", () -> {
            subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService, encryptionKeysConfiguration);
            subject.mapUuidsToKeys(encryptionService);
          });
        });

        describe("when decrypting with the wrong key returns an incorrect canary value", () -> {
          beforeEach(() -> {
            when(encryptionService.decrypt(activeKey, nonMatchingCanary.getEncryptedValue(), nonMatchingCanary.getNonce()))
                .thenReturn("different-canary-value");
            when(encryptionKeyCanaryDataService.save(any(EncryptionKeyCanary.class)))
                .thenReturn(activeEncryptionKeyCanary);

            subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService, encryptionKeysConfiguration);
            subject.mapUuidsToKeys(encryptionService);
          });

          it("should create a canary for the key", () -> {
            assertCanaryValueWasEncryptedAndSavedToDatabase();
          });
        });
      });

      describe("when there is a matching canary in the database", () -> {
        beforeEach(() -> {
          when(encryptionKeyCanaryDataService.findAll()).thenReturn(asList(activeEncryptionKeyCanary));
          when(encryptionService.decrypt(activeKey, activeEncryptionKeyCanary.getEncryptedValue(), activeEncryptionKeyCanary.getNonce()))
              .thenReturn(CANARY_VALUE);

          subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService, encryptionKeysConfiguration);
          subject.mapUuidsToKeys(encryptionService);
        });

        it("should map the key to the matching canary", () -> {
          assertThat(subject.getKeyForUuid(activeCanaryUUID), equalTo(activeKey));
        });

        it("should not re-encrypt the canary value", () -> {
          verify(encryptionService, times(0)).encrypt(eq(activeKey), any(String.class));
        });

        it("sets the matching canary's UUID as active", () -> {
          assertThat(subject.getActiveUuid(), equalTo(activeCanaryUUID));
        });
      });
    });

    describe("when there are multiple keys", () -> {
      beforeEach(() -> {
        when(encryptionKeysConfiguration.getKeys()).thenReturn(asList(existingKey1Data, activeKeyData, existingKey2Data));
      });

      describe("when there are matching canaries for all of the keys", () -> {
        it("should return a map between the matching canaries and keys", () -> {
          assertThat(subject.getKeyForUuid(activeCanaryUUID), equalTo(activeKey));
          assertThat(subject.getKeyForUuid(existingCanaryUUID1), equalTo(existingKey1));
          assertThat(subject.getKeyForUuid(existingCanaryUUID2), equalTo(existingKey2));
        });

        it("should set the active key's canary UUID as active", () -> {
          assertThat(subject.getActiveUuid(), equalTo(activeCanaryUUID));
        });
      });

      describe("when there is a non-active key that does not have a matching canary", () -> {
        beforeEach(() -> {
          when(encryptionKeyCanaryDataService.findAll()).thenReturn(asList(existingEncryptionKeyCanary1, activeEncryptionKeyCanary));

          subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService, encryptionKeysConfiguration);
          subject.mapUuidsToKeys(encryptionService);
        });

        it("should not create a canary for the key", () -> {
          verify(encryptionKeyCanaryDataService, times(0)).save(any(EncryptionKeyCanary.class));
        });

        it("should not include it in the returned map", () -> {
          assertThat(subject.getKeyForUuid(activeCanaryUUID), equalTo(activeKey));
          assertThat(subject.getKeyForUuid(existingCanaryUUID1), equalTo(existingKey1));
        });

        it("should set the active key's canary UUID as active", () -> {
          assertThat(subject.getActiveUuid(), equalTo(activeCanaryUUID));
        });
      });
    });
  }

  private void assertCanaryValueWasEncryptedAndSavedToDatabase() throws Exception {
    ArgumentCaptor<EncryptionKeyCanary> argumentCaptor = ArgumentCaptor.forClass(EncryptionKeyCanary.class);
    verify(encryptionKeyCanaryDataService, times(1)).save(argumentCaptor.capture());

    EncryptionKeyCanary encryptionKeyCanary = argumentCaptor.getValue();
    assertThat(encryptionKeyCanary.getEncryptedValue(), equalTo("fake-encrypted-value".getBytes()));
    assertThat(encryptionKeyCanary.getNonce(), equalTo("fake-nonce".getBytes()));
    verify(encryptionService, times(1)).encrypt(activeKey, CANARY_VALUE);
  }

  private EncryptionKeyCanary createEncryptionCanary(UUID canaryUuid, String encryptedValue, String nonce, Key encryptionKey)
      throws Exception {
    EncryptionKeyCanary encryptionKeyCanary = new EncryptionKeyCanary();
    encryptionKeyCanary.setUuid(canaryUuid);
    encryptionKeyCanary.setEncryptedValue(encryptedValue.getBytes());
    encryptionKeyCanary.setNonce(nonce.getBytes());
    when(encryptionService.decrypt(encryptionKey, encryptedValue.getBytes(), nonce.getBytes()))
        .thenReturn(CANARY_VALUE);
    return encryptionKeyCanary;
  }
}
