package org.cloudfoundry.credhub.keyusage;

import java.util.Map;
import java.util.Map.Entry;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.google.common.collect.ImmutableMap;
import org.cloudfoundry.credhub.services.CredentialVersionDataService;
import org.cloudfoundry.credhub.services.EncryptionKeySet;

@RestController
@RequestMapping(
  path = KeyUsageController.ENDPOINT,
  produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class KeyUsageController {

  public static final String ENDPOINT = "/api/v1/key-usage";

  private final CredentialVersionDataService credentialVersionDataService;
  private final EncryptionKeySet keySet;

  @Autowired
  public KeyUsageController(
    final CredentialVersionDataService credentialVersionDataService,
    final EncryptionKeySet keySet) {
    super();
    this.credentialVersionDataService = credentialVersionDataService;
    this.keySet = keySet;
  }

  @RequestMapping(method = RequestMethod.GET, path = "")
  public ResponseEntity<Map> getKeyUsages() {
    Long totalCredCount = 0L;
    final Map<UUID, Long> countByEncryptionKey = credentialVersionDataService.countByEncryptionKey();
    for (int i = 0; i < countByEncryptionKey.size(); i++) {
      totalCredCount += countByEncryptionKey.values().toArray(new Long[countByEncryptionKey.values().size()])[i];
    }

    final Long activeKeyCreds = countByEncryptionKey.getOrDefault(keySet.getActive().getUuid(), 0L);

    Long credsEncryptedByKnownKeys = 0L;

    for (final Entry<UUID, Long> entrySet : countByEncryptionKey.entrySet()) {
      if (keySet.getUuids().contains(entrySet.getKey())) {
        credsEncryptedByKnownKeys += countByEncryptionKey.get(entrySet.getKey());
      }
    }

    final Long unknownKeyCreds = totalCredCount - credsEncryptedByKnownKeys;
    final Long inactiveKeyCreds = totalCredCount - (activeKeyCreds + unknownKeyCreds);

    return new ResponseEntity<>(
      ImmutableMap.of(
        "active_key", activeKeyCreds,
        "inactive_keys", inactiveKeyCreds,
        "unknown_keys", unknownKeyCreds),
      HttpStatus.OK);
  }
}
