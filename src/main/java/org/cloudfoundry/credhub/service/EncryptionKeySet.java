package org.cloudfoundry.credhub.service;

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

  public EncryptionKeySet() {
    reset();
  }

  void add(UUID uuid, Key key) {
    keys.put(uuid, key);
  }

  void setActive(UUID uuid) {
    activeUUID = uuid;
  }

  Key get(UUID uuid) {
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

  public void reset() {
    keys = new HashMap<>();
    activeUUID = null;
  }
}
