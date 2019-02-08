package org.cloudfoundry.credhub.services;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

@SuppressWarnings("PMD.NullAssignment")
@Component
public class EncryptionKeySet {

  private Map<UUID, EncryptionKey> keys;
  private UUID activeUUID;
  private EncryptionKeyCanaryMapper canaryMapper;

  // For testing
  public EncryptionKeySet() {
    super();
    keys = new HashMap<>();
  }

  @Autowired
  public EncryptionKeySet(final EncryptionKeyCanaryMapper canaryMapper) throws Exception {
    super();
    this.canaryMapper = canaryMapper;
    reload();
  }

  public void add(final EncryptionKey key) {
    keys.put(key.getUuid(), key);
  }

  public EncryptionKey get(final UUID uuid) {
    return keys.get(uuid);
  }

  public Collection<EncryptionKey> getKeys() {
    return keys.values();
  }

  @Bean
  public EncryptionKey getActive() {
    return keys.get(activeUUID);
  }

  public void setActive(final UUID uuid) {
    activeUUID = uuid;
  }

  public List<UUID> getInactiveUuids() {
    return keys.keySet().stream().filter(uuid -> !uuid.equals(activeUUID)).collect(Collectors.toList());
  }

  public Collection<UUID> getUuids() {
    return keys.keySet();
  }

  public void reload() throws Exception {
    keys = new HashMap<>();
    activeUUID = null;
    canaryMapper.mapUuidsToKeys(this);
  }
}
