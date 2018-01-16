package org.cloudfoundry.credhub.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class EncryptionKeySet {

  private Map<UUID, Key> keys;
  private UUID activeUUID;
  private EncryptionKeyCanaryMapper canaryMapper;

  // For testing
  public EncryptionKeySet() {
    keys = new HashMap<>();
  }

  @Autowired
  public EncryptionKeySet(EncryptionKeyCanaryMapper canaryMapper) {
    this.canaryMapper = canaryMapper;
    reload();
  }

  public void add(UUID uuid, Key key) {
    keys.put(uuid, key);
  }

  public void setActive(UUID uuid) {
    activeUUID = uuid;
  }

  public Key get(UUID uuid) {
    return keys.get(uuid);
  }

  public Collection<Key> getKeys() {
    return keys.values();
  }

  public UUID getActive() {
    return activeUUID;
  }

  public List<UUID> getInactive() {
    return keys.keySet().stream().filter(uuid -> !uuid.equals(activeUUID)).collect(Collectors.toList());
  }

  public Collection<UUID> getUuids() {
    return keys.keySet();
  }

  public Key getActiveKey() {
    return keys.get(activeUUID);
  }

  public void reload() {
    keys = new HashMap<>();
    activeUUID = null;
    canaryMapper.mapUuidsToKeys(this);
  }
}
