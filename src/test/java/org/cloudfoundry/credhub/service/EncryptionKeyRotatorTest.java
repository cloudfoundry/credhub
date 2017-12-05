package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.data.EncryptedValueDataService;
import org.cloudfoundry.credhub.data.EncryptionKeyCanaryDataService;
import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentCaptor;
import org.springframework.data.domain.SliceImpl;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static com.google.common.collect.Lists.newArrayList;
import static com.jayway.jsonassert.impl.matcher.IsCollectionWithSize.hasSize;
import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
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
  private EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;
  private UUID oldUuid;

  @Before
  public void beforeEach() {
    oldUuid = UUID.randomUUID();

    encryptedValueDataService = mock(EncryptedValueDataService.class);

    encryptedValue1 = mock(EncryptedValue.class);
    encryptedValue2 = mock(EncryptedValue.class);
    encryptedValue3 = mock(EncryptedValue.class);

    encryptionKeyCanaryMapper = mock(EncryptionKeyCanaryMapper.class);
    when(encryptionKeyCanaryMapper.getCanaryUuidsWithKnownAndInactiveKeys())
        .thenReturn(newArrayList(oldUuid));
    encryptionKeyCanaryDataService = mock(EncryptionKeyCanaryDataService.class);
    when(encryptedValueDataService.findEncryptedWithAvailableInactiveKey())
        .thenReturn(new SliceImpl<>(asList(encryptedValue1, encryptedValue2)))
        .thenReturn(new SliceImpl<>(asList(encryptedValue3)))
        .thenReturn(new SliceImpl<>(new ArrayList<>()));

    final EncryptionKeyRotator encryptionKeyRotator = new EncryptionKeyRotator(encryptedValueDataService,
        encryptionKeyCanaryMapper, encryptionKeyCanaryDataService);

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
    ArgumentCaptor<List> argumentCaptor = ArgumentCaptor.forClass(List.class);

    verify(encryptionKeyCanaryDataService).delete(argumentCaptor.capture());

    List<UUID> deletedUuids = argumentCaptor.getValue();

    assertThat(deletedUuids, hasSize(1));
    assertThat(deletedUuids, hasItem(oldUuid));
  }
}
