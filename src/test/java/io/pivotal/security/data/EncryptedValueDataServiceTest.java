package io.pivotal.security.data;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.entity.EncryptedValue;
import io.pivotal.security.repository.EncryptedValueRepository;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.util.DatabaseProfileResolver;
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
  EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;

  @MockBean
  EncryptedValueRepository encryptedValueRepository;

  @MockBean
  Encryptor encryptor;

  EncryptedValueDataService subject;

  @Before
  public void beforeEach() {
    subject = new EncryptedValueDataService(encryptionKeyCanaryMapper, encryptedValueRepository,
        encryptor);
  }

  @Test
  public void countAllNotEncryptedByActiveKey() throws Exception {
    UUID activeKeyUUID = UUID.randomUUID();
    when(encryptionKeyCanaryMapper.getActiveUuid()).thenReturn(activeKeyUUID);

    subject.countAllNotEncryptedByActiveKey();

    verify(encryptedValueRepository).countByEncryptionKeyUuidNot(activeKeyUUID);
  }

  @Test
  public void findEncryptedWithAvailableInactiveKey() throws Exception {
    List<UUID> canaryUuids = Collections.singletonList(UUID.randomUUID());
    Slice<EncryptedValue> encryptedValues = new SliceImpl(Collections.singletonList(new EncryptedValue()));
    when(encryptionKeyCanaryMapper.getCanaryUuidsWithKnownAndInactiveKeys()).thenReturn(canaryUuids);
    when(encryptedValueRepository.findByEncryptionKeyUuidIn(eq(canaryUuids), any())).thenReturn(encryptedValues);

    assertThat(subject.findEncryptedWithAvailableInactiveKey(), equalTo(encryptedValues));
  }

  @Test
  public void rotate() throws Exception {
    Encryption newEncryption = new Encryption(UUID.randomUUID(), "new value".getBytes(), "nonce".getBytes());
    EncryptedValue value = new EncryptedValue();
    value.setEncryptedValue("bytes".getBytes());
    value.setEncryptionKeyUuid(UUID.randomUUID());
    value.setNonce("nonce".getBytes());
    when(encryptor.decrypt(any(Encryption.class))).thenReturn("new value");
    when(encryptor.encrypt("new value")).thenReturn(newEncryption);
    subject.rotate(value);

    verify(encryptedValueRepository).saveAndFlush(value);
    assertThat(value.getEncryptedValue(), equalTo("new value".getBytes()));
  }

}
