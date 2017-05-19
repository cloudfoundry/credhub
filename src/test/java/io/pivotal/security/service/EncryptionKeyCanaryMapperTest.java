package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.config.EncryptionKeysConfiguration;
import io.pivotal.security.data.EncryptionKeyCanaryDataService;
import io.pivotal.security.entity.EncryptionKeyCanary;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;

import java.security.Key;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import javax.crypto.AEADBadTagException;
import javax.crypto.IllegalBlockSizeException;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static io.pivotal.security.service.EncryptionKeyCanaryMapper.CANARY_VALUE;
import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.arrayContainingInAnyOrder;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class EncryptionKeyCanaryMapperTest {

  private EncryptionKeyCanaryMapper subject;
  private EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;
  private EncryptionService encryptionService;
  private UUID activeCanaryUuid;
  private UUID existingCanaryUuid1;
  private UUID existingCanaryUuid2;
  private UUID unknownCanaryUuid;
  private Key activeKey;
  private Key existingKey1;
  private Key existingKey2;
  private Key unknownKey;
  private KeyProxy activeKeyProxy;
  private KeyProxy existingKey1Proxy;
  private KeyProxy existingKey2Proxy;
  private EncryptionKeyMetadata activeKeyData;
  private EncryptionKeyMetadata existingKey1Data;
  private EncryptionKeyMetadata existingKey2Data;
  private EncryptionKeyCanary activeKeyCanary;
  private EncryptionKeyCanary existingKeyCanary1;
  private EncryptionKeyCanary existingKeyCanary2;
  private EncryptionKeyCanary unknownCanary;

  private EncryptionKeysConfiguration encryptionKeysConfiguration;

  {
    beforeEach(() -> {
      encryptionKeyCanaryDataService = mock(EncryptionKeyCanaryDataService.class);
      encryptionService = mock(EncryptionService.class);
      encryptionKeysConfiguration = mock(EncryptionKeysConfiguration.class);

      activeCanaryUuid = UUID.randomUUID();
      existingCanaryUuid1 = UUID.randomUUID();
      existingCanaryUuid2 = UUID.randomUUID();
      unknownCanaryUuid = UUID.randomUUID();

      activeKeyData = new EncryptionKeyMetadata();
      activeKeyData.setEncryptionPassword("this-is-active");
      activeKeyData.setActive(true);

      existingKey1Data = new EncryptionKeyMetadata();
      existingKey1Data.setEncryptionPassword("existing-key-1");
      existingKey1Data.setActive(false);

      existingKey2Data = new EncryptionKeyMetadata();
      existingKey2Data.setEncryptionPassword("existing-key-2");
      existingKey2Data.setActive(false);

      activeKey = mock(Key.class, "active key");
      existingKey1 = mock(Key.class, "key 1");
      existingKey2 = mock(Key.class, "key 2");
      unknownKey = mock(Key.class, "key 3");
      activeKeyProxy = mock(KeyProxy.class);
      existingKey1Proxy = mock(KeyProxy.class);
      existingKey2Proxy = mock(KeyProxy.class);

      activeKeyCanary = createEncryptionCanary(activeCanaryUuid, "fake-active-encrypted-value",
          "fake-active-nonce", activeKey);
      existingKeyCanary1 = createEncryptionCanary(existingCanaryUuid1,
          "fake-existing-encrypted-value1", "fake-existing-nonce1", existingKey1);
      existingKeyCanary2 = createEncryptionCanary(existingCanaryUuid2,
          "fake-existing-encrypted-value2", "fake-existing-nonce2", existingKey2);
      unknownCanary = createEncryptionCanary(unknownCanaryUuid, "fake-existing-encrypted-value3",
          "fake-existing-nonce3", unknownKey);

      when(encryptionService.encrypt(null, activeKey, CANARY_VALUE))
          .thenReturn(
              new Encryption(null, "fake-encrypted-value".getBytes(), "fake-nonce".getBytes()));
      when(encryptionKeysConfiguration.getKeys()).thenReturn(newArrayList(
          existingKey1Data,
          activeKeyData,
          existingKey2Data
      ));
      when(encryptionService.createKeyProxy(eq(activeKeyData))).thenReturn(activeKeyProxy);
      when(encryptionService.createKeyProxy(eq(existingKey1Data))).thenReturn(existingKey1Proxy);
      when(encryptionService.createKeyProxy(eq(existingKey2Data))).thenReturn(existingKey2Proxy);

      when(activeKeyProxy.matchesCanary(eq(activeKeyCanary))).thenReturn(true);
      when(existingKey1Proxy.matchesCanary(eq(existingKeyCanary1))).thenReturn(true);
      when(existingKey2Proxy.matchesCanary(eq(existingKeyCanary2))).thenReturn(true);
      when(activeKeyProxy.getKey()).thenReturn(activeKey);
      when(existingKey1Proxy.getKey()).thenReturn(existingKey1);
      when(existingKey2Proxy.getKey()).thenReturn(existingKey2);

      when(encryptionKeyCanaryDataService.findAll())
          .thenReturn(asList(existingKeyCanary1, activeKeyCanary, existingKeyCanary2));

      subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
          encryptionKeysConfiguration, encryptionService);
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

      itThrowsWithMessage("a warning about no active key", RuntimeException.class,
          "No active key was found", () -> {
            subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
                encryptionKeysConfiguration, encryptionService);
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
              .thenReturn(activeKeyCanary);

          subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
              encryptionKeysConfiguration, encryptionService);
        });

        it("creates and saves a canary to the database", () -> {
          assertCanaryValueWasEncryptedAndSavedToDatabase();
        });

        it("maps between the new canary and the active key", () -> {
          assertThat(subject.getKeyForUuid(activeCanaryUuid), equalTo(activeKey));
          assertThat(subject.getUuidForKey(activeKey), equalTo(activeCanaryUuid));
        });

        it("sets the new canary's UUID as active", () -> {
          assertThat(subject.getActiveUuid(), equalTo(activeCanaryUuid));
        });
      });

      describe("when there is no matching canary in the database", () -> {
        EncryptionKeyCanary nonMatchingCanary = new EncryptionKeyCanary();

        beforeEach(() -> {
          nonMatchingCanary.setUuid(UUID.randomUUID());
          nonMatchingCanary.setEncryptedCanaryValue("fake-non-matching-encrypted-value".getBytes());
          nonMatchingCanary.setNonce("fake-non-matching-nonce".getBytes());

          when(encryptionKeyCanaryDataService.findAll())
              .thenReturn(Arrays.asList(nonMatchingCanary));
        });

        describe("when decrypting with the wrong key raises AEADBadTagException -- internal",
            () -> {
              beforeEach(() -> {
                when(encryptionService.decrypt(activeKey, nonMatchingCanary.getEncryptedCanaryValue(),
                    nonMatchingCanary.getNonce()))
                    .thenThrow(new AEADBadTagException());
                when(encryptionKeyCanaryDataService.save(any(EncryptionKeyCanary.class)))
                    .thenReturn(activeKeyCanary);

                subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
                    encryptionKeysConfiguration, encryptionService);
              });

              it("should create a canary for the key", () -> {
                assertCanaryValueWasEncryptedAndSavedToDatabase();
              });
            });

        describe(
            "when decrypting with the wrong key raises a known "
                + "IllegalBlockSizeException error -- HSM",
            () -> {
              beforeEach(() -> {
                when(encryptionService.decrypt(activeKey, nonMatchingCanary.getEncryptedCanaryValue(),
                    nonMatchingCanary.getNonce()))
                    .thenThrow(new IllegalBlockSizeException(
                        "Could not process input data: function 'C_Decrypt' returns 0x40"));
                when(encryptionKeyCanaryDataService.save(any(EncryptionKeyCanary.class)))
                    .thenReturn(activeKeyCanary);

                subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
                    encryptionKeysConfiguration, encryptionService);
              });

              it("should create a canary for the key", () -> {
                assertCanaryValueWasEncryptedAndSavedToDatabase();
              });
            });

        describe(
            "when decrypting with the wrong key raises an unknown "
                + "IllegalBlockSizeException error -- HSM",
            () -> {
              beforeEach(() -> {
                when(activeKeyProxy.matchesCanary(nonMatchingCanary))
                    .thenThrow(new RuntimeException(new IllegalBlockSizeException(
                        "I don't know what 0x41 means and neither do you")));
                when(encryptionKeyCanaryDataService.save(any(EncryptionKeyCanary.class)))
                    .thenReturn(activeKeyCanary);
              });

              itThrowsWithMessage("something", RuntimeException.class,
                  "javax.crypto.IllegalBlockSizeException:"
                      + " I don't know what 0x41 means and neither do you",
                  () -> {
                    subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
                        encryptionKeysConfiguration, encryptionService);
                  });
            });

        describe("when decrypting with the wrong key returns an incorrect canary value", () -> {
          beforeEach(() -> {
            when(encryptionService.decrypt(activeKey, nonMatchingCanary.getEncryptedCanaryValue(),
                nonMatchingCanary.getNonce()))
                .thenReturn("different-canary-value");
            when(encryptionKeyCanaryDataService.save(any(EncryptionKeyCanary.class)))
                .thenReturn(activeKeyCanary);

            subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
                encryptionKeysConfiguration, encryptionService);
          });

          it("should create a canary for the key", () -> {
            assertCanaryValueWasEncryptedAndSavedToDatabase();
          });
        });
      });

      describe("when there is a matching canary in the database", () -> {
        beforeEach(() -> {
          when(encryptionKeyCanaryDataService.findAll()).thenReturn(asList(activeKeyCanary));
          when(encryptionService
              .decrypt(activeKey, activeKeyCanary.getEncryptedCanaryValue(), activeKeyCanary.getNonce()))
              .thenReturn(CANARY_VALUE);

          subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
              encryptionKeysConfiguration, encryptionService);
        });

        it("should map the key to the matching canary", () -> {
          assertThat(subject.getKeyForUuid(activeCanaryUuid), equalTo(activeKey));
        });

        it("should not re-encrypt the canary value", () -> {
          verify(encryptionService, times(0))
              .encrypt(eq(activeCanaryUuid), eq(activeKey), any(String.class));
        });

        it("sets the matching canary's UUID as active", () -> {
          assertThat(subject.getActiveUuid(), equalTo(activeCanaryUuid));
        });
      });
    });

    describe("when there are multiple keys", () -> {
      beforeEach(() -> {
        when(encryptionKeysConfiguration.getKeys())
            .thenReturn(asList(existingKey1Data, activeKeyData, existingKey2Data));
      });

      describe("when there are matching canaries for all of the keys", () -> {
        it("should return a map between the matching canaries and keys", () -> {
          assertThat(subject.getKeyForUuid(activeCanaryUuid), equalTo(activeKey));
          assertThat(subject.getKeyForUuid(existingCanaryUuid1), equalTo(existingKey1));
          assertThat(subject.getKeyForUuid(existingCanaryUuid2), equalTo(existingKey2));
          assertThat(subject.getCanaryUuidsWithKnownAndInactiveKeys().toArray(),
              arrayContainingInAnyOrder(existingCanaryUuid1, existingCanaryUuid2));
        });

        it("should set the active key's canary UUID as active", () -> {
          assertThat(subject.getActiveUuid(), equalTo(activeCanaryUuid));
        });
      });

      describe("when there is a non-active key that does not have a matching canary", () -> {
        beforeEach(() -> {
          when(encryptionKeyCanaryDataService.findAll())
              .thenReturn(asList(existingKeyCanary1, activeKeyCanary));

          subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
              encryptionKeysConfiguration, encryptionService);
        });

        it("should not create a canary for the key", () -> {
          verify(encryptionKeyCanaryDataService, times(0)).save(any(EncryptionKeyCanary.class));
        });

        it("should not include it in the returned map", () -> {
          assertThat(subject.getKeyForUuid(activeCanaryUuid), equalTo(activeKey));
          assertThat(subject.getKeyForUuid(existingCanaryUuid1), equalTo(existingKey1));
          assertThat(subject.getKeyForUuid(existingCanaryUuid2), equalTo(null));
        });

        it("should set the active key's canary UUID as active", () -> {
          assertThat(subject.getActiveUuid(), equalTo(activeCanaryUuid));
        });

        it("should not include the UUID in getCanaryUuidsWithKnownAndInactiveKeys", () -> {
          assertThat(subject.getCanaryUuidsWithKnownAndInactiveKeys().toArray(),
              arrayContainingInAnyOrder(existingCanaryUuid1));
        });
      });

      describe("when there are canaries for keys that we don't have", () -> {
        beforeEach(() -> {
          when(encryptionKeyCanaryDataService.findAll())
              .thenReturn(asList(unknownCanary, activeKeyCanary));

          subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
              encryptionKeysConfiguration, encryptionService);
        });

        it("should not include it in the returned map", () -> {
          assertThat(subject.getKeyForUuid(activeCanaryUuid), equalTo(activeKey));
          assertThat(subject.getKeyForUuid(unknownCanaryUuid), equalTo(null));
        });

        it("should set the active key's canary UUID as active", () -> {
          assertThat(subject.getActiveUuid(), equalTo(activeCanaryUuid));
        });

        it("should not include the UUID in getCanaryUuidsWithKnownAndInactiveKeys", () -> {
          assertThat(subject.getCanaryUuidsWithKnownAndInactiveKeys().size(), equalTo(0));
        });
      });
    });
  }

  private void assertCanaryValueWasEncryptedAndSavedToDatabase() throws Exception {
    ArgumentCaptor<EncryptionKeyCanary> argumentCaptor = ArgumentCaptor
        .forClass(EncryptionKeyCanary.class);
    verify(encryptionKeyCanaryDataService).save(argumentCaptor.capture());

    EncryptionKeyCanary encryptionKeyCanary = argumentCaptor.getValue();
    assertThat(encryptionKeyCanary.getEncryptedCanaryValue(), equalTo("fake-encrypted-value".getBytes()));
    assertThat(encryptionKeyCanary.getNonce(), equalTo("fake-nonce".getBytes()));
    verify(encryptionService, times(1)).encrypt(null, activeKey, CANARY_VALUE);
  }

  private EncryptionKeyCanary createEncryptionCanary(UUID canaryUuid, String encryptedValue,
      String nonce, Key encryptionKey)
      throws Exception {
    EncryptionKeyCanary encryptionKeyCanary = new EncryptionKeyCanary();
    encryptionKeyCanary.setUuid(canaryUuid);
    encryptionKeyCanary.setEncryptedCanaryValue(encryptedValue.getBytes());
    encryptionKeyCanary.setNonce(nonce.getBytes());
    when(encryptionService.decrypt(encryptionKey, encryptedValue.getBytes(), nonce.getBytes()))
        .thenReturn(CANARY_VALUE);
    return encryptionKeyCanary;
  }
}
