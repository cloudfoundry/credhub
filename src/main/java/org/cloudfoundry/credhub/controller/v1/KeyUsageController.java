package org.cloudfoundry.credhub.controller.v1;

import com.google.common.collect.ImmutableMap;
import org.cloudfoundry.credhub.data.CredentialVersionDataService;
import org.cloudfoundry.credhub.service.EncryptionKeySet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping(
    path = "api/v1/key-usage",
    produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class KeyUsageController {

  private final CredentialVersionDataService credentialVersionDataService;
  private final EncryptionKeySet keySet;

  @Autowired
  public KeyUsageController(
      CredentialVersionDataService credentialVersionDataService,
      EncryptionKeySet keySet) {
    this.credentialVersionDataService = credentialVersionDataService;
    this.keySet = keySet;
  }

  @RequestMapping(method = RequestMethod.GET, path = "")
  public ResponseEntity<Map> getKeyUsages() {
    Long totalCredCount = 0L;
    final HashMap<UUID, Long> countByEncryptionKey = credentialVersionDataService.countByEncryptionKey();
    for (int i=0; i<countByEncryptionKey.size(); i++) {
      totalCredCount += countByEncryptionKey.values().toArray(new Long[countByEncryptionKey.values().size()])[i];
    }

    Long activeKeyCreds = countByEncryptionKey.getOrDefault(keySet.getActive().getUuid(), 0L);

    Long credsEncryptedByKnownKeys = 0L;
    for (UUID encryptionKeyUuid : countByEncryptionKey.keySet()) {
      if (keySet.getUuids().contains(encryptionKeyUuid)) {
        credsEncryptedByKnownKeys += countByEncryptionKey.get(encryptionKeyUuid);
      }
    }

    Long unknownKeyCreds = totalCredCount - credsEncryptedByKnownKeys;
    Long inactiveKeyCreds = totalCredCount - (activeKeyCreds + unknownKeyCreds);

    return new ResponseEntity<>(
        ImmutableMap.of(
            "active_key", activeKeyCreds,
            "inactive_keys", inactiveKeyCreds,
            "unknown_keys", unknownKeyCreds),
        HttpStatus.OK);
  }
}
