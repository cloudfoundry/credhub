package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.data.EncryptedValueDataService;
import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.springframework.data.domain.SliceImpl;

import java.security.Key;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static com.google.common.collect.Lists.newArrayList;
import static java.util.Arrays.asList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class EncryptionKeyRotatorTest {

  private EncryptedValueDataService encryptedValueDataService;

  private EncryptedValue encryptedValue1;
  private EncryptedValue encryptedValue2;
  private EncryptedValue encryptedValue3;
  private EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;
  private UUID oldUuid;
  private List<UUID> inactiveCanaries;
  private EncryptionKeySet keySet;

  @Before
  public void beforeEach() {
    oldUuid = UUID.randomUUID();
    UUID activeUuid = UUID.randomUUID();

    encryptedValueDataService = mock(EncryptedValueDataService.class);
    keySet = new EncryptionKeySet();
    keySet.add(new EncryptionKey(mock(EncryptionService.class), oldUuid, mock(Key.class)));
    keySet.add(new EncryptionKey(mock(EncryptionService.class), activeUuid, mock(Key.class)));
    keySet.setActive(activeUuid);

    encryptedValue1 = mock(EncryptedValue.class);
    encryptedValue2 = mock(EncryptedValue.class);
    encryptedValue3 = mock(EncryptedValue.class);

    encryptionKeyCanaryMapper = mock(EncryptionKeyCanaryMapper.class);
    inactiveCanaries = newArrayList(oldUuid);

    when(encryptedValueDataService.findByCanaryUuids(inactiveCanaries))
        .thenReturn(new SliceImpl<>(asList(encryptedValue1, encryptedValue2)))
        .thenReturn(new SliceImpl<>(asList(encryptedValue3)))
        .thenReturn(new SliceImpl<>(new ArrayList<>()));

    final EncryptionKeyRotator encryptionKeyRotator = new EncryptionKeyRotator(encryptedValueDataService,
        encryptionKeyCanaryMapper,
        keySet);

    encryptionKeyRotator.rotate();
  }

  @Test
  public void shouldRotateAllTheCredentialsThatWereEncryptedWithAnAvailableOldKey() {
    verify(encryptedValueDataService).rotate(encryptedValue1);
    verify(encryptedValueDataService).rotate(encryptedValue2);
    verify(encryptedValueDataService).rotate(encryptedValue3);
  }

  @Test
  public void deletesTheUnusedCanaries() {
    verify(encryptionKeyCanaryMapper).delete(inactiveCanaries);
  }

}
