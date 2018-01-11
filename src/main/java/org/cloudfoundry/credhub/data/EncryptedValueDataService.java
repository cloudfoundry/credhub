package org.cloudfoundry.credhub.data;

import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.repository.EncryptedValueRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Slice;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

import static org.cloudfoundry.credhub.repository.EncryptedValueRepository.BATCH_SIZE;

@Service
public class EncryptedValueDataService {

  private final EncryptedValueRepository encryptedValueRepository;
  private final Encryptor encryptor;

  @Autowired
  protected EncryptedValueDataService(
      EncryptedValueRepository encryptedValueRepository,
      Encryptor encryptor) {
    this.encryptedValueRepository = encryptedValueRepository;
    this.encryptor = encryptor;
  }

  public Long countAllByCanaryUuid(UUID uuid) {
    return encryptedValueRepository.countByEncryptionKeyUuidNot(uuid);
  }

  public Slice<EncryptedValue> findByCanaryUuids(List<UUID> canaryUuids) {
    return encryptedValueRepository
        .findByEncryptionKeyUuidIn(canaryUuids,
            new PageRequest(0, BATCH_SIZE)
        );
  }

  public void rotate(EncryptedValue encryptedValue) {
    String decryptedValue = encryptor.decrypt(encryptedValue);
    EncryptedValue newEncryptedValue = encryptor.encrypt(decryptedValue);
    newEncryptedValue.setUuid(encryptedValue.getUuid());
    encryptedValueRepository.saveAndFlush(newEncryptedValue);
  }
}
