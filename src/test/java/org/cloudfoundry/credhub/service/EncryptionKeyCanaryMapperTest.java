package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.config.EncryptionKeysConfiguration;
import org.cloudfoundry.credhub.data.EncryptionKeyCanaryDataService;
import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.entity.EncryptionKeyCanary;
import org.cloudfoundry.credhub.util.TimedRetry;
import org.assertj.core.util.Lists;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentCaptor;

import javax.crypto.AEADBadTagException;
import javax.crypto.IllegalBlockSizeException;
import java.security.Key;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;

import static com.google.common.collect.Lists.newArrayList;
import static org.cloudfoundry.credhub.service.EncryptionKeyCanaryMapper.CANARY_VALUE;
import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.arrayContainingInAnyOrder;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyLong;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
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
  private TimedRetry timedRetry;

  private EncryptionKeysConfiguration encryptionKeysConfiguration;

  @Before()
  public void beforeEach() throws Exception {
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
        .thenReturn(new EncryptedValue(
            null,
            "fake-encrypted-value",
            "fake-nonce"));
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

    timedRetry = mock(TimedRetry.class);
    when(timedRetry.retryEverySecondUntil(anyLong(), any(Supplier.class)))
        .thenAnswer(answer -> {
          Supplier<Boolean> retryableOperation = answer.getArgumentAt(1, Supplier.class);
          for (int i = 0; i < 10; ++i) {
            if (retryableOperation.get()) {
              return true;
            }
          }
          return false;
        });
  }

  @Test
  public void mapCanariesToKeys_shouldCreateTheKeys() {
    subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
        encryptionKeysConfiguration, encryptionService, timedRetry, true);

    final List<Key> keys = subject.getKeys();
    assertThat(keys.size(), equalTo(3));
    assertThat(keys, containsInAnyOrder(
        activeKey, existingKey1, existingKey2
    ));
  }

  @Test
  public void mapCanariesToKeys_shouldContainAReferenceToActiveKey() {
    subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
        encryptionKeysConfiguration, encryptionService, timedRetry, true);
    assertThat(subject.getKeys(), hasItem(subject.getActiveKey()));
  }

  @Test
  public void mapCanariesToKeys_whenThereIsNoActiveKey_raisesAnException() {
    when(encryptionKeysConfiguration.getKeys()).thenReturn(asList());

    try {
      subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
          encryptionKeysConfiguration, encryptionService, timedRetry, true);
    } catch (Exception e) {
      assertThat(e.getMessage(), equalTo("No active key was found"));
    }
  }

  @Test
  public void mapCanariesToKeys_whenTheActiveKeyIsTheOnlyKey_andThereAreNoCanariesInTheDatabase_andKeyCreationIsEnabled_createsAndSavesACanaryToTheDatabase()
      throws Exception {
    when(encryptionKeysConfiguration.getKeys()).thenReturn(asList(activeKeyData));
    List<EncryptionKeyCanary> canaries = newArrayList();
    when(encryptionKeyCanaryDataService.findAll()).thenReturn(canaries);

    when(encryptionKeyCanaryDataService.save(any(EncryptionKeyCanary.class)))
        .thenAnswer(invocation -> {
          canaries.add(activeKeyCanary);
          return activeKeyCanary;
        });

    subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
        encryptionKeysConfiguration, encryptionService, timedRetry, true);

    assertCanaryValueWasEncryptedAndSavedToDatabase();
    assertThat(subject.getKeyForUuid(activeCanaryUuid), equalTo(activeKey));
    assertThat(subject.getActiveUuid(), equalTo(activeCanaryUuid));
  }

  @Test
  public void mapCanariesToKeys_whenTheActiveKeyIsTheOnlyKey_andThereAreNoCanariesInTheDatabase_andKeyCreationIsDisabled_waitsForAnotherProcessToPutACanaryToTheDatabase()
      throws Exception {
    when(encryptionKeysConfiguration.getKeys()).thenReturn(asList(activeKeyData));
    List<EncryptionKeyCanary> canaries = newArrayList();
    when(encryptionKeyCanaryDataService.findAll()).thenReturn(canaries);

    when(encryptionKeyCanaryDataService.save(any(EncryptionKeyCanary.class)))
        .thenAnswer(invocation -> {
          canaries.add(activeKeyCanary);
          return activeKeyCanary;
        });

    List<EncryptionKeyCanary> noCanaries = newArrayList();
    List<EncryptionKeyCanary> oneCanary = Lists.newArrayList(activeKeyCanary);
    when(encryptionKeyCanaryDataService.findAll())
        .thenReturn(noCanaries)
        .thenReturn(oneCanary);
    subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
        encryptionKeysConfiguration, encryptionService, timedRetry, false);

    verify(encryptionKeyCanaryDataService, never()).save(any());
    verify(timedRetry).retryEverySecondUntil(eq(600L), any());
    assertThat(subject.getActiveUuid(), equalTo(activeCanaryUuid));
  }

  @Test
  public void mapCanariesToKeys_whenTheActiveKeyIsTheOnlyKey_whenThereIsNoMatchingCanaryInTheDatabase_whenDecryptingWithTheWrongKeyRaisesAnInternalException_itShouldCreateACanaryForTheKey()
      throws Exception {
    when(encryptionKeysConfiguration.getKeys()).thenReturn(asList(activeKeyData));
    EncryptionKeyCanary nonMatchingCanary = new EncryptionKeyCanary();

    nonMatchingCanary.setUuid(UUID.randomUUID());
    nonMatchingCanary.setEncryptedCanaryValue("fake-non-matching-encrypted-value".getBytes());
    nonMatchingCanary.setNonce("fake-non-matching-nonce".getBytes());

    when(encryptionKeyCanaryDataService.findAll())
        .thenReturn(Arrays.asList(nonMatchingCanary));

    when(encryptionService
        .decrypt(activeKey, nonMatchingCanary.getEncryptedCanaryValue(),
            nonMatchingCanary.getNonce()))
        .thenThrow(new AEADBadTagException());
    when(encryptionKeyCanaryDataService.save(any(EncryptionKeyCanary.class)))
        .thenReturn(activeKeyCanary);

    subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
        encryptionKeysConfiguration, encryptionService, timedRetry, true);

    assertCanaryValueWasEncryptedAndSavedToDatabase();
  }

  @Test
  public void mapCanariesToKeys_whenTheActiveKeyIsTheOnlyKey_whenThereIsNoMatchingCanaryInTheDatabase_whenDecryptingWithTheWrongKeyRaisesAnHSMException_itShouldCreateACanaryForTheKey()
      throws Exception {
    when(encryptionKeysConfiguration.getKeys()).thenReturn(asList(activeKeyData));
    EncryptionKeyCanary nonMatchingCanary = new EncryptionKeyCanary();

    nonMatchingCanary.setUuid(UUID.randomUUID());
    nonMatchingCanary.setEncryptedCanaryValue("fake-non-matching-encrypted-value".getBytes());
    nonMatchingCanary.setNonce("fake-non-matching-nonce".getBytes());

    when(encryptionKeyCanaryDataService.findAll())
        .thenReturn(Arrays.asList(nonMatchingCanary));

    when(encryptionService
        .decrypt(activeKey, nonMatchingCanary.getEncryptedCanaryValue(),
            nonMatchingCanary.getNonce()))
        .thenThrow(new IllegalBlockSizeException(
            "Could not process input data: function 'C_Decrypt' returns 0x40"));
    when(encryptionKeyCanaryDataService.save(any(EncryptionKeyCanary.class)))
        .thenReturn(activeKeyCanary);

    subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
        encryptionKeysConfiguration, encryptionService, timedRetry, true);

    assertCanaryValueWasEncryptedAndSavedToDatabase();
  }

  @Test
  public void mapCanariesToKeys_whenTheActiveKeyIsTheOnlyKey_whenThereIsNoMatchingCanaryInTheDatabase_whenDecryptingWithTheWrongKeyRaisesAnHSMException_throwsTheException()
      throws Exception {
    when(encryptionKeysConfiguration.getKeys()).thenReturn(asList(activeKeyData));
    EncryptionKeyCanary nonMatchingCanary = new EncryptionKeyCanary();

    nonMatchingCanary.setUuid(UUID.randomUUID());
    nonMatchingCanary.setEncryptedCanaryValue("fake-non-matching-encrypted-value".getBytes());
    nonMatchingCanary.setNonce("fake-non-matching-nonce".getBytes());

    when(encryptionKeyCanaryDataService.findAll())
        .thenReturn(Arrays.asList(nonMatchingCanary));

    when(activeKeyProxy.matchesCanary(nonMatchingCanary))
        .thenThrow(new RuntimeException(new IllegalBlockSizeException(
            "I don't know what 0x41 means and neither do you")));
    when(encryptionKeyCanaryDataService.save(any(EncryptionKeyCanary.class)))
        .thenReturn(activeKeyCanary);

    try {
      subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
          encryptionKeysConfiguration, encryptionService, timedRetry, true);
    } catch (RuntimeException e) {
      assertThat(e.getMessage(), equalTo(
          "javax.crypto.IllegalBlockSizeException: I don't know what 0x41 means and neither do you"));
    }
  }

  @Test
  public void mapCanariesToKeys_whenTheActiveKeyIsTheOnlyKey_whenThereIsNoMatchingCanaryInTheDatabase_whenDecryptingWithTheWrongKeyReturnsAnIncorrectCanaryValue_createsACanaryForTheKey()
      throws Exception {
    when(encryptionKeysConfiguration.getKeys()).thenReturn(asList(activeKeyData));
    EncryptionKeyCanary nonMatchingCanary = new EncryptionKeyCanary();

    nonMatchingCanary.setUuid(UUID.randomUUID());
    nonMatchingCanary.setEncryptedCanaryValue("fake-non-matching-encrypted-value".getBytes());
    nonMatchingCanary.setNonce("fake-non-matching-nonce".getBytes());

    when(encryptionKeyCanaryDataService.findAll())
        .thenReturn(Arrays.asList(nonMatchingCanary));

    when(encryptionService.decrypt(activeKey, nonMatchingCanary.getEncryptedCanaryValue(),
        nonMatchingCanary.getNonce()))
        .thenReturn("different-canary-value");
    when(encryptionKeyCanaryDataService.save(any(EncryptionKeyCanary.class)))
        .thenReturn(activeKeyCanary);

    subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
        encryptionKeysConfiguration, encryptionService, timedRetry, true);

    assertCanaryValueWasEncryptedAndSavedToDatabase();
  }

  @Test
  public void mapCanariesToKeys_whenTheActiveKeyIsTheOnlyKey_whenThereIsAMatchingCanaryInTheDatabase_shouldMapTheKeyToTheMatchingCanary()
      throws Exception {
    when(encryptionKeysConfiguration.getKeys()).thenReturn(asList(activeKeyData));
    when(encryptionKeyCanaryDataService.findAll()).thenReturn(asList(activeKeyCanary));
    when(encryptionService
        .decrypt(activeKey, activeKeyCanary.getEncryptedCanaryValue(),
            activeKeyCanary.getNonce()))
        .thenReturn(CANARY_VALUE);

    subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
        encryptionKeysConfiguration, encryptionService, timedRetry, true);

    assertThat(subject.getKeyForUuid(activeCanaryUuid), equalTo(activeKey));
    verify(encryptionService, times(0))
        .encrypt(eq(activeCanaryUuid), eq(activeKey), any(String.class));
    assertThat(subject.getActiveUuid(), equalTo(activeCanaryUuid));
  }

  @Test
  public void mapCanariesToKeys_whenThereAreMultipleKeys_andMatchingCanariesForEveryKey_itShouldReturnAMapBetweenMatchingCanariesAndKeys()
      throws Exception {
    when(encryptionKeysConfiguration.getKeys())
        .thenReturn(asList(existingKey1Data, activeKeyData, existingKey2Data));
    subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
        encryptionKeysConfiguration, encryptionService, timedRetry, true);

    assertThat(subject.getKeyForUuid(activeCanaryUuid), equalTo(activeKey));
    assertThat(subject.getKeyForUuid(existingCanaryUuid1), equalTo(existingKey1));
    assertThat(subject.getKeyForUuid(existingCanaryUuid2), equalTo(existingKey2));
    assertThat(subject.getCanaryUuidsWithKnownAndInactiveKeys().toArray(),
        arrayContainingInAnyOrder(existingCanaryUuid1, existingCanaryUuid2));
    assertThat(subject.getActiveUuid(), equalTo(activeCanaryUuid));
  }

  @Test
  public void mapCanariesToKeys_whenThereAreMultipleKeys_andCanariesForKeysWeDontHave_itShouldNotBeIncluded()
      throws Exception {
    when(encryptionKeyCanaryDataService.findAll())
        .thenReturn(asList(unknownCanary, activeKeyCanary));

    subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
        encryptionKeysConfiguration, encryptionService, timedRetry, true);

    assertThat(subject.getKeyForUuid(activeCanaryUuid), equalTo(activeKey));
    assertThat(subject.getKeyForUuid(unknownCanaryUuid), equalTo(null));
    assertThat(subject.getActiveUuid(), equalTo(activeCanaryUuid));
    assertThat(subject.getCanaryUuidsWithKnownAndInactiveKeys().size(), equalTo(0));
  }

  private void assertCanaryValueWasEncryptedAndSavedToDatabase() throws Exception {
    ArgumentCaptor<EncryptionKeyCanary> argumentCaptor = ArgumentCaptor
        .forClass(EncryptionKeyCanary.class);
    verify(encryptionKeyCanaryDataService).save(argumentCaptor.capture());

    EncryptionKeyCanary encryptionKeyCanary = argumentCaptor.getValue();
    assertThat(encryptionKeyCanary.getEncryptedCanaryValue(),
        equalTo("fake-encrypted-value".getBytes()));
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
