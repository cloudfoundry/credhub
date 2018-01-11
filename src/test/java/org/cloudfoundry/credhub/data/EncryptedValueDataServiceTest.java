package org.cloudfoundry.credhub.data;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.repository.EncryptedValueRepository;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.Slice;
import org.springframework.data.domain.SliceImpl;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class EncryptedValueDataServiceTest {

  @MockBean
  EncryptedValueRepository encryptedValueRepository;

  @MockBean
  Encryptor encryptor;

  EncryptedValueDataService subject;

  @Before
  public void beforeEach() {
    subject = new EncryptedValueDataService(encryptedValueRepository, encryptor);
  }

  @Test
  public void countAllByCanaryUuid() throws Exception {
    UUID uuid = UUID.randomUUID();

    subject.countAllByCanaryUuid(uuid);

    verify(encryptedValueRepository).countByEncryptionKeyUuidNot(uuid);
  }

  @Test
  public void findByCanaryUuids() throws Exception {
    List<UUID> canaryUuids = Collections.singletonList(UUID.randomUUID());
    Slice<EncryptedValue> encryptedValues = new SliceImpl(Collections.singletonList(new EncryptedValue()));
    when(encryptedValueRepository.findByEncryptionKeyUuidIn(eq(canaryUuids), any())).thenReturn(encryptedValues);

    assertThat(subject.findByCanaryUuids(canaryUuids), equalTo(encryptedValues));
  }

  @Test
  public void rotate() throws Exception {
    EncryptedValue newEncryption = new EncryptedValue(UUID.randomUUID(), "expected value".getBytes(),
        "nonce".getBytes());
    EncryptedValue value = new EncryptedValue();
    value.setEncryptedValue("bytes".getBytes());
    value.setEncryptionKeyUuid(UUID.randomUUID());
    value.setNonce("nonce".getBytes());
    when(encryptor.decrypt(any(EncryptedValue.class))).thenReturn("expected value");
    when(encryptor.encrypt("expected value")).thenReturn(newEncryption);
    subject.rotate(value);

    verify(encryptedValueRepository).saveAndFlush(newEncryption);
    assertThat(newEncryption.getUuid(), equalTo(value.getUuid()));
  }

}
