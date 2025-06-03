package org.cloudfoundry.credhub.services;

import java.security.Key;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import javax.crypto.AEADBadTagException;
import javax.crypto.IllegalBlockSizeException;

import org.assertj.core.util.Lists;
import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.config.EncryptionKeyProvider;
import org.cloudfoundry.credhub.config.EncryptionKeysConfiguration;
import org.cloudfoundry.credhub.config.ProviderType;
import org.cloudfoundry.credhub.data.EncryptionKeyCanaryDataService;
import org.cloudfoundry.credhub.entities.EncryptedValue;
import org.cloudfoundry.credhub.entities.EncryptionKeyCanary;
import org.cloudfoundry.credhub.util.TimedRetry;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentCaptor;

import static com.google.common.collect.Lists.newArrayList;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.cloudfoundry.credhub.services.EncryptionKeyCanaryMapper.CANARY_VALUE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.arrayContainingInAnyOrder;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsIterableContaining.hasItem;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class EncryptionKeyCanaryMapperTest {
  private EncryptionKeyCanaryMapper subject;
  private EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;
  private EncryptionKeySet keySet;
  private InternalEncryptionService encryptionService;
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
  private EncryptionKeyProvider activeProvider;
  private EncryptionKeyMetadata existingKey1Data;
  private EncryptionKeyMetadata existingKey2Data;
  private EncryptionKeyCanary activeKeyCanary;
  private EncryptionKeyCanary existingKeyCanary1;
  private EncryptionKeyCanary existingKeyCanary2;
  private EncryptionKeyCanary unknownCanary;
  private TimedRetry timedRetry;
  private EncryptionKeysConfiguration encryptionKeysConfiguration;
  private EncryptionProviderFactory providerFactory;

  @Before
  public void beforeEach() throws Exception {
    encryptionKeyCanaryDataService = mock(EncryptionKeyCanaryDataService.class);
    encryptionService = mock(InternalEncryptionService.class);
    encryptionKeysConfiguration = mock(EncryptionKeysConfiguration.class);
    keySet = new EncryptionKeySet();
    providerFactory = mock(EncryptionProviderFactory.class);

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

    activeProvider = new EncryptionKeyProvider();
    activeProvider.setProviderName("int");
    activeProvider.setProviderType(ProviderType.INTERNAL);
    activeProvider.setKeys(Arrays.asList(new EncryptionKeyMetadata[]{activeKeyData, existingKey1Data, existingKey2Data}));

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

    final List<EncryptionKeyProvider> providers = new ArrayList<>();
    final EncryptionKeyProvider provider = new EncryptionKeyProvider();
    final List<EncryptionKeyMetadata> keys = newArrayList(
      existingKey1Data,
      activeKeyData,
      existingKey2Data
    );
    provider.setKeys(keys);
    providers.add(provider);

    when(encryptionService.encrypt(null, activeKey, CANARY_VALUE))
      .thenReturn(
        new EncryptedValue(
        null,
        "fake-encrypted-value",
        "fake-nonce"
        )
      );
    when(encryptionKeysConfiguration.getProviders()).thenReturn(providers);
    when(providerFactory.getEncryptionService(activeProvider)).thenReturn(encryptionService);

    when(encryptionService.createKeyProxy(activeKeyData)).thenReturn(activeKeyProxy);
    when(encryptionService.createKeyProxy(existingKey1Data)).thenReturn(existingKey1Proxy);
    when(encryptionService.createKeyProxy(existingKey2Data)).thenReturn(existingKey2Proxy);

    when(activeKeyProxy.matchesCanary(activeKeyCanary)).thenReturn(true);
    when(existingKey1Proxy.matchesCanary(existingKeyCanary1)).thenReturn(true);
    when(existingKey2Proxy.matchesCanary(existingKeyCanary2)).thenReturn(true);
    when(activeKeyProxy.getKey()).thenReturn(activeKey);
    when(existingKey1Proxy.getKey()).thenReturn(existingKey1);
    when(existingKey2Proxy.getKey()).thenReturn(existingKey2);

    when(encryptionKeyCanaryDataService.findAll())
      .thenReturn(new ArrayList<>(asArrayList(existingKeyCanary1, activeKeyCanary, existingKeyCanary2)));

    timedRetry = mock(TimedRetry.class);
    when(timedRetry.retryEverySecondUntil(anyLong(), any(Supplier.class)))
      .thenAnswer(answer -> {
        final Supplier<Boolean> retryableOperation = answer.getArgument(1);
        for (int i = 0; i < 10; ++i) {
          if (retryableOperation.get()) {
            return true;
          }
        }
        return false;
      });
  }

  @Test
  public void mapUuidsToKeys_shouldCreateTheKeys() throws Exception {
    when(encryptionKeysConfiguration.isKeyCreationEnabled()).thenReturn(true);
    when(encryptionKeysConfiguration.getProviders()).thenReturn(asList(activeProvider));
    subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
      encryptionKeysConfiguration, timedRetry, providerFactory);
    subject.mapUuidsToKeys(keySet);

    final Collection<EncryptionKey> keys = keySet.getKeys();
    assertThat(keys.size(), equalTo(3));
    assertThat(keys.stream().map(EncryptionKey::getKey).collect(Collectors.toList()), containsInAnyOrder(
      activeKey, existingKey1, existingKey2
    ));
  }

  @Test
  public void mapUuidsToKeys_shouldContainAReferenceToActiveKey() throws Exception {
    when(encryptionKeysConfiguration.isKeyCreationEnabled()).thenReturn(true);
    when(encryptionKeysConfiguration.getProviders()).thenReturn(asList(activeProvider));

    subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
      encryptionKeysConfiguration, timedRetry, providerFactory);
    subject.mapUuidsToKeys(keySet);

    assertThat(keySet.getKeys(), hasItem(keySet.getActive()));
  }

  @Test
  public void mapUuidsToKeys_whenTheActiveKeyIsTheOnlyKey_andThereAreNoCanariesInTheDatabase_andKeyCreationIsEnabled_createsAndSavesACanaryToTheDatabase()
    throws Exception {
    when(encryptionKeysConfiguration.isKeyCreationEnabled()).thenReturn(true);
    when(encryptionKeysConfiguration.getProviders().get(0).getKeys()).thenReturn(asList(activeKeyData));
    when(encryptionKeysConfiguration.getProviders()).thenReturn(asList(activeProvider));
    final List<EncryptionKeyCanary> canaries = newArrayList();
    when(encryptionKeyCanaryDataService.findAll()).thenReturn(canaries);

    when(encryptionKeyCanaryDataService.save(any(EncryptionKeyCanary.class)))
      .thenAnswer(invocation -> {
        canaries.add(activeKeyCanary);
        return activeKeyCanary;
      });
    when(encryptionService.encrypt(any(EncryptionKey.class), eq(CANARY_VALUE))).thenReturn(new EncryptedValue(
      null,
      "fake-encrypted-value",
      "fake-nonce"));

    subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
      encryptionKeysConfiguration, timedRetry, providerFactory);
    subject.mapUuidsToKeys(keySet);

    assertCanaryValueWasEncryptedAndSavedToDatabase();
    assertThat(keySet.get(activeCanaryUuid).getKey(), equalTo(activeKey));
    assertThat(keySet.getActive().getUuid(), equalTo(activeCanaryUuid));
  }

  @Test
  public void mapUuidsToKeys_whenTheActiveKeyIsTheOnlyKey_andThereAreNoCanariesInTheDatabase_andKeyCreationIsDisabled_waitsForAnotherProcessToPutACanaryToTheDatabase()
    throws Exception {
    when(encryptionKeysConfiguration.isKeyCreationEnabled()).thenReturn(false);
    when(encryptionKeysConfiguration.getProviders().get(0).getKeys()).thenReturn(asList(activeKeyData));
    when(encryptionKeysConfiguration.getProviders()).thenReturn(asList(activeProvider));

    final List<EncryptionKeyCanary> noCanaries = newArrayList();
    final List<EncryptionKeyCanary> oneCanary = Lists.newArrayList(activeKeyCanary);
    when(encryptionKeyCanaryDataService.findAll())
      .thenReturn(noCanaries)
      .thenReturn(noCanaries)
      .thenReturn(oneCanary);
    subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
      encryptionKeysConfiguration, timedRetry, providerFactory);
    subject.mapUuidsToKeys(keySet);

    verify(encryptionKeyCanaryDataService, never()).save(any());
    verify(timedRetry).retryEverySecondUntil(eq(600L), any());
    assertThat(keySet.getActive().getUuid(), equalTo(activeCanaryUuid));
  }

  @Test
  public void mapUuidsToKeys_whenKeyCreationIsDisabled_AndNoKeyIsEverCreated_ThrowsAnException() throws Exception {
    when(encryptionKeysConfiguration.isKeyCreationEnabled()).thenReturn(false);
    when(encryptionKeysConfiguration.getProviders().get(0).getKeys()).thenReturn(asList(activeKeyData));
    when(encryptionKeysConfiguration.getProviders()).thenReturn(asList(activeProvider));
    when(encryptionKeyCanaryDataService.findAll()).thenReturn(newArrayList());
    subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
      encryptionKeysConfiguration, timedRetry, providerFactory);

    assertThatThrownBy(() -> subject.mapUuidsToKeys(keySet))
            .hasMessageMatching("Timed out waiting for active key canary to be created");
  }

  @Test
  public void mapUuidsToKeys_whenTheActiveKeyIsTheOnlyKey_whenThereIsNoMatchingCanaryInTheDatabase_whenDecryptingWithTheWrongKeyRaisesAnInternalException_itShouldCreateACanaryForTheKey()
    throws Exception {
    when(encryptionKeysConfiguration.isKeyCreationEnabled()).thenReturn(true);
    when(encryptionKeysConfiguration.getProviders().get(0).getKeys()).thenReturn(asList(activeKeyData));
    when(encryptionKeysConfiguration.getProviders()).thenReturn(asList(activeProvider));
    final EncryptionKeyCanary nonMatchingCanary = new EncryptionKeyCanary();

    nonMatchingCanary.setUuid(UUID.randomUUID());
    nonMatchingCanary.setEncryptedCanaryValue("fake-non-matching-encrypted-value".getBytes(UTF_8));
    nonMatchingCanary.setNonce("fake-non-matching-nonce".getBytes(UTF_8));

    when(encryptionKeyCanaryDataService.findAll())
      .thenReturn(asArrayList(nonMatchingCanary));

    when(encryptionService
      .decrypt(activeKey, nonMatchingCanary.getEncryptedCanaryValue(),
        nonMatchingCanary.getNonce()))
      .thenThrow(new AEADBadTagException());
    when(encryptionKeyCanaryDataService.save(any(EncryptionKeyCanary.class)))
      .thenReturn(activeKeyCanary);
    when(encryptionService.encrypt(any(EncryptionKey.class), eq(CANARY_VALUE))).thenReturn(new EncryptedValue(
      null,
      "fake-encrypted-value",
      "fake-nonce"));

    subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
      encryptionKeysConfiguration, timedRetry, providerFactory);

    subject.mapUuidsToKeys(keySet);

    assertCanaryValueWasEncryptedAndSavedToDatabase();
  }

  @Test
  public void mapUuidsToKeys_whenTheActiveKeyIsTheOnlyKey_whenThereIsNoMatchingCanaryInTheDatabase_whenDecryptingWithTheWrongKeyRaisesAnHSMException_itShouldCreateACanaryForTheKey()
    throws Exception {
    when(encryptionKeysConfiguration.isKeyCreationEnabled()).thenReturn(true);
    when(encryptionKeysConfiguration.getProviders().get(0).getKeys()).thenReturn(asList(activeKeyData));
    when(encryptionKeysConfiguration.getProviders()).thenReturn(asList(activeProvider));
    final EncryptionKeyCanary nonMatchingCanary = new EncryptionKeyCanary();

    nonMatchingCanary.setUuid(UUID.randomUUID());
    nonMatchingCanary.setEncryptedCanaryValue("fake-non-matching-encrypted-value".getBytes(UTF_8));
    nonMatchingCanary.setNonce("fake-non-matching-nonce".getBytes(UTF_8));

    when(encryptionKeyCanaryDataService.findAll())
      .thenReturn(asArrayList(nonMatchingCanary));

    when(encryptionService
      .decrypt(activeKey, nonMatchingCanary.getEncryptedCanaryValue(),
        nonMatchingCanary.getNonce()))
      .thenThrow(new IllegalBlockSizeException(
        "Could not process input data: function 'C_Decrypt' returns 0x40"));
    when(encryptionKeyCanaryDataService.save(any(EncryptionKeyCanary.class)))
      .thenReturn(activeKeyCanary);
    when(encryptionService.encrypt(any(EncryptionKey.class), eq(CANARY_VALUE))).thenReturn(new EncryptedValue(
      null,
      "fake-encrypted-value",
      "fake-nonce"));

    subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
      encryptionKeysConfiguration, timedRetry, providerFactory);
    subject.mapUuidsToKeys(keySet);

    assertCanaryValueWasEncryptedAndSavedToDatabase();
  }

  @Test
  public void mapUuidsToKeys_whenThereIsNoActiveKey() throws Exception {
    final List<EncryptionKeyMetadata> keys = asList(existingKey1Data, existingKey2Data);
    activeProvider.setKeys(keys);
    final List<EncryptionKeyProvider> providers = asList(activeProvider);

    when(encryptionKeysConfiguration.isKeyCreationEnabled()).thenReturn(true);
    when(encryptionKeysConfiguration.getProviders()).thenReturn(providers);
    subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
      encryptionKeysConfiguration, timedRetry, providerFactory);

    assertThatThrownBy(() -> subject.mapUuidsToKeys(keySet))
            .hasMessageMatching("No active key was found");
  }

  @Test
  public void mapUuidsToKeys_whenTheActiveKeyIsTheOnlyKey_whenThereIsNoMatchingCanaryInTheDatabase_whenDecryptingWithTheWrongKeyRaisesAnHSMException_throwsTheException()
    throws Exception {
    when(encryptionKeysConfiguration.isKeyCreationEnabled()).thenReturn(true);
    when(encryptionKeysConfiguration.getProviders().get(0).getKeys()).thenReturn(asList(activeKeyData));
    when(encryptionKeysConfiguration.getProviders()).thenReturn(asList(activeProvider));
    final EncryptionKeyCanary nonMatchingCanary = new EncryptionKeyCanary();

    nonMatchingCanary.setUuid(UUID.randomUUID());
    nonMatchingCanary.setEncryptedCanaryValue("fake-non-matching-encrypted-value".getBytes(UTF_8));
    nonMatchingCanary.setNonce("fake-non-matching-nonce".getBytes(UTF_8));

    when(encryptionKeyCanaryDataService.findAll())
      .thenReturn(asArrayList(nonMatchingCanary));

    when(activeKeyProxy.matchesCanary(nonMatchingCanary))
      .thenThrow(new RuntimeException(new IllegalBlockSizeException(
        "I don't know what 0x41 means and neither do you")));
    when(encryptionKeyCanaryDataService.save(any(EncryptionKeyCanary.class)))
      .thenReturn(activeKeyCanary);

    subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
      encryptionKeysConfiguration, timedRetry, providerFactory);

    assertThatThrownBy(() -> subject.mapUuidsToKeys(keySet))
            .hasMessageMatching(
                    "javax.crypto.IllegalBlockSizeException: I don't know what 0x41 means and neither do you");
  }

  @Test
  public void mapUuidsToKeys_whenTheActiveKeyIsTheOnlyKey_whenThereIsNoMatchingCanaryInTheDatabase_whenDecryptingWithTheWrongKeyReturnsAnIncorrectCanaryValue_createsACanaryForTheKey()
    throws Exception {
    when(encryptionKeysConfiguration.isKeyCreationEnabled()).thenReturn(true);
    when(encryptionKeysConfiguration.getProviders().get(0).getKeys()).thenReturn(asList(activeKeyData));
    when(encryptionKeysConfiguration.getProviders()).thenReturn(asList(activeProvider));
    final EncryptionKeyCanary nonMatchingCanary = new EncryptionKeyCanary();

    nonMatchingCanary.setUuid(UUID.randomUUID());
    nonMatchingCanary.setEncryptedCanaryValue("fake-non-matching-encrypted-value".getBytes(UTF_8));
    nonMatchingCanary.setNonce("fake-non-matching-nonce".getBytes(UTF_8));

    when(encryptionKeyCanaryDataService.findAll())
      .thenReturn(asArrayList(nonMatchingCanary));

    when(encryptionService.decrypt(activeKey, nonMatchingCanary.getEncryptedCanaryValue(),
      nonMatchingCanary.getNonce()))
      .thenReturn("different-canary-value");
    when(encryptionKeyCanaryDataService.save(any(EncryptionKeyCanary.class)))
      .thenReturn(activeKeyCanary);
    when(encryptionService.encrypt(any(EncryptionKey.class), eq(CANARY_VALUE))).thenReturn(new EncryptedValue(
      null,
      "fake-encrypted-value",
      "fake-nonce"));

    subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
      encryptionKeysConfiguration, timedRetry, providerFactory);

    subject.mapUuidsToKeys(keySet);

    assertCanaryValueWasEncryptedAndSavedToDatabase();
  }

  @Test
  public void mapUuidsToKeys_whenTheActiveKeyIsTheOnlyKey_whenThereIsAMatchingCanaryInTheDatabase_shouldMapTheKeyToTheMatchingCanary()
    throws Exception {
    when(encryptionKeysConfiguration.isKeyCreationEnabled()).thenReturn(true);
    when(encryptionKeysConfiguration.getProviders().get(0).getKeys()).thenReturn(asList(activeKeyData));
    when(encryptionKeysConfiguration.getProviders()).thenReturn(asList(activeProvider));
    when(encryptionKeyCanaryDataService.findAll()).thenReturn(asArrayList(activeKeyCanary));
    when(encryptionService
      .decrypt(activeKey, activeKeyCanary.getEncryptedCanaryValue(),
        activeKeyCanary.getNonce()))
      .thenReturn(CANARY_VALUE);

    subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
      encryptionKeysConfiguration, timedRetry, providerFactory);

    subject.mapUuidsToKeys(keySet);

    assertThat(keySet.get(activeCanaryUuid).getKey(), equalTo(activeKey));
    verify(encryptionService, times(0))
      .encrypt(eq(activeCanaryUuid), eq(activeKey), any(String.class));
    assertThat(keySet.getActive().getUuid(), equalTo(activeCanaryUuid));
  }

  @Test
  public void mapUuidsToKeys_whenThereAreMultipleKeys_andMatchingCanariesForEveryKey_itShouldReturnAMapBetweenMatchingCanariesAndKeys()
    throws Exception {

    activeProvider.setKeys(asList(existingKey1Data, activeKeyData, existingKey2Data));
    final List<EncryptionKeyProvider> providers = asList(activeProvider);

    when(encryptionKeysConfiguration.isKeyCreationEnabled()).thenReturn(true);
    when(encryptionKeysConfiguration.getProviders()).thenReturn(providers);

    subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
      encryptionKeysConfiguration, timedRetry, providerFactory);
    subject.mapUuidsToKeys(keySet);

    assertThat(keySet.get(activeCanaryUuid).getKey(), equalTo(activeKey));
    assertThat(keySet.get(existingCanaryUuid1).getKey(), equalTo(existingKey1));
    assertThat(keySet.get(existingCanaryUuid2).getKey(), equalTo(existingKey2));
    assertThat(keySet.getInactiveUuids().toArray(),
      arrayContainingInAnyOrder(existingCanaryUuid1, existingCanaryUuid2));
    assertThat(keySet.getActive().getUuid(), equalTo(activeCanaryUuid));
  }

  @Test
  public void mapUuidsToKeys_whenThereAreMultipleKeys_andCanariesForKeysWeDontHave_itShouldNotBeIncluded()
    throws Exception {
    when(encryptionKeysConfiguration.isKeyCreationEnabled()).thenReturn(true);
    when(encryptionKeysConfiguration.getProviders()).thenReturn(asList(activeProvider));
    when(encryptionKeyCanaryDataService.findAll())
      .thenReturn(asArrayList(unknownCanary, activeKeyCanary));

    subject = new EncryptionKeyCanaryMapper(encryptionKeyCanaryDataService,
      encryptionKeysConfiguration, timedRetry, providerFactory);
    subject.mapUuidsToKeys(keySet);

    assertThat(keySet.get(activeCanaryUuid).getKey(), equalTo(activeKey));
    assertThat(keySet.get(unknownCanaryUuid), equalTo(null));
    assertThat(keySet.getActive().getUuid(), equalTo(activeCanaryUuid));
    assertThat(keySet.getInactiveUuids().size(), equalTo(0));
  }

  private List<EncryptionKeyCanary> asArrayList(final EncryptionKeyCanary... canaries) {
    final List<EncryptionKeyCanary> list = new ArrayList<>();
    for (final EncryptionKeyCanary canary : canaries) {
      list.add(canary);
    }
    return list;
  }

  private void assertCanaryValueWasEncryptedAndSavedToDatabase() throws Exception {
    final ArgumentCaptor<EncryptionKeyCanary> argumentCaptor = ArgumentCaptor
      .forClass(EncryptionKeyCanary.class);
    verify(encryptionKeyCanaryDataService).save(argumentCaptor.capture());

    final EncryptionKeyCanary encryptionKeyCanary = argumentCaptor.getValue();
    assertThat(encryptionKeyCanary.getEncryptedCanaryValue(),
      equalTo("fake-encrypted-value".getBytes(UTF_8)));
    assertThat(encryptionKeyCanary.getNonce(), equalTo("fake-nonce".getBytes(UTF_8)));
    verify(encryptionService, times(1)).encrypt(any(EncryptionKey.class), eq(CANARY_VALUE));
  }

  private EncryptionKeyCanary createEncryptionCanary(final UUID canaryUuid, final String encryptedValue,
                                                     final String nonce, final Key encryptionKey)
    throws Exception {
    final EncryptionKeyCanary encryptionKeyCanary = new EncryptionKeyCanary();
    encryptionKeyCanary.setUuid(canaryUuid);
    encryptionKeyCanary.setEncryptedCanaryValue(encryptedValue.getBytes(UTF_8));
    encryptionKeyCanary.setNonce(nonce.getBytes(UTF_8));
    when(encryptionService.decrypt(encryptionKey, encryptedValue.getBytes(UTF_8), nonce.getBytes(UTF_8)))
      .thenReturn(CANARY_VALUE);
    return encryptionKeyCanary;
  }
}
