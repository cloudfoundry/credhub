package org.cloudfoundry.credhub.data;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.Slice;
import org.springframework.data.domain.SliceImpl;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.DatabaseProfileResolver;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.entities.EncryptedValue;
import org.cloudfoundry.credhub.repositories.EncryptedValueRepository;
import org.cloudfoundry.credhub.utils.StringUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredhubTestApp.class)
public class EncryptedValueDataServiceTest {

  @MockBean
  private EncryptedValueRepository encryptedValueRepository;

  @MockBean
  private Encryptor encryptor;

  private EncryptedValueDataService subject;

  @Before
  public void beforeEach() {
    subject = new EncryptedValueDataService(encryptedValueRepository, encryptor);
  }

  @Test
  public void countAllByCanaryUuid() throws Exception {
    final UUID uuid = UUID.randomUUID();

    subject.countAllByCanaryUuid(uuid);

    verify(encryptedValueRepository).countByEncryptionKeyUuidNot(uuid);
  }

  @Test
  public void findByCanaryUuids() throws Exception {
    final List<UUID> canaryUuids = Collections.singletonList(UUID.randomUUID());
    final Slice<EncryptedValue> encryptedValues = new SliceImpl(Collections.singletonList(new EncryptedValue()));
    when(encryptedValueRepository.findByEncryptionKeyUuidIn(eq(canaryUuids), any())).thenReturn(encryptedValues);

    assertThat(subject.findByCanaryUuids(canaryUuids), equalTo(encryptedValues));
  }

  @Test
  public void rotate() throws Exception {
    final EncryptedValue newEncryption = new EncryptedValue(UUID.randomUUID(), "expected value".getBytes(StringUtil.UTF_8),
      "nonce".getBytes(StringUtil.UTF_8));
    final EncryptedValue value = new EncryptedValue();
    value.setEncryptedValue("bytes".getBytes(StringUtil.UTF_8));
    value.setEncryptionKeyUuid(UUID.randomUUID());
    value.setNonce("nonce".getBytes(StringUtil.UTF_8));
    when(encryptor.decrypt(any(EncryptedValue.class))).thenReturn("expected value");
    when(encryptor.encrypt("expected value")).thenReturn(newEncryption);
    subject.rotate(value);

    verify(encryptedValueRepository).saveAndFlush(newEncryption);
    assertThat(newEncryption.getUuid(), equalTo(value.getUuid()));
  }

}
