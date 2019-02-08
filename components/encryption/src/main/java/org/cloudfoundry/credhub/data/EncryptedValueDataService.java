package org.cloudfoundry.credhub.data;

import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Slice;
import org.springframework.stereotype.Service;

import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.entities.EncryptedValue;
import org.cloudfoundry.credhub.repositories.EncryptedValueRepository;

@Service
public class EncryptedValueDataService {

  private final EncryptedValueRepository encryptedValueRepository;
  private final Encryptor encryptor;

  @Autowired
  protected EncryptedValueDataService(
    final EncryptedValueRepository encryptedValueRepository,
    final Encryptor encryptor) {
    super();
    this.encryptedValueRepository = encryptedValueRepository;
    this.encryptor = encryptor;
  }

  public Long countAllByCanaryUuid(final UUID uuid) {
    return encryptedValueRepository.countByEncryptionKeyUuidNot(uuid);
  }

  public Slice<EncryptedValue> findByCanaryUuids(final List<UUID> canaryUuids) {
    return encryptedValueRepository
      .findByEncryptionKeyUuidIn(canaryUuids,
        PageRequest.of(0, EncryptedValueRepository.BATCH_SIZE)
      );
  }

  public void rotate(final EncryptedValue encryptedValue) {
    final String decryptedValue = encryptor.decrypt(encryptedValue);
    final EncryptedValue newEncryptedValue = encryptor.encrypt(decryptedValue);
    newEncryptedValue.setUuid(encryptedValue.getUuid());
    encryptedValueRepository.saveAndFlush(newEncryptedValue);
  }
}
