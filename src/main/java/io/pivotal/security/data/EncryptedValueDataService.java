package io.pivotal.security.data;

import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.entity.EncryptedValue;
import io.pivotal.security.repository.EncryptedValueRepository;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Slice;
import org.springframework.stereotype.Service;

import java.util.UUID;

import static io.pivotal.security.repository.EncryptedValueRepository.BATCH_SIZE;

@Service
public class EncryptedValueDataService {
  private final EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;
  private final EncryptedValueRepository encryptedValueRepository;
  private final Encryptor encryptor;

  @Autowired
  protected EncryptedValueDataService(
      EncryptionKeyCanaryMapper encryptionKeyCanaryMapper,
      EncryptedValueRepository encryptedValueRepository,
      Encryptor encryptor) {
    this.encryptionKeyCanaryMapper = encryptionKeyCanaryMapper;
    this.encryptedValueRepository = encryptedValueRepository;
    this.encryptor = encryptor;
  }

  public Long countAllNotEncryptedByActiveKey() {
    UUID activeUuid = encryptionKeyCanaryMapper.getActiveUuid();

    return encryptedValueRepository.countByEncryptionKeyUuidNot(activeUuid);
  }

  public Slice<EncryptedValue> findEncryptedWithAvailableInactiveKey() {
    return encryptedValueRepository
        .findByEncryptionKeyUuidIn(
            encryptionKeyCanaryMapper.getCanaryUuidsWithKnownAndInactiveKeys(),
            new PageRequest(0, BATCH_SIZE)
        );
  }

  public void rotate (EncryptedValue encryptedValue){
    Encryption encryption = new Encryption(encryptedValue.getEncryptionKeyUuid(), encryptedValue.getEncryptedValue(), encryptedValue.getNonce());
    String decrypted = encryptor.decrypt(encryption);
    Encryption newEncrypted = encryptor.encrypt(decrypted);
    encryptedValue.setEncryptedValue(newEncrypted.encryptedValue);
    encryptedValue.setEncryptionKeyUuid(newEncrypted.canaryUuid);
    encryptedValue.setNonce(newEncrypted.nonce);
    encryptedValueRepository.saveAndFlush(encryptedValue);
  }
}
