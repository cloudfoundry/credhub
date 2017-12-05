package org.cloudfoundry.credhub.controller.v1;

import com.google.common.collect.ImmutableMap;
import org.cloudfoundry.credhub.data.CredentialVersionDataService;
import org.cloudfoundry.credhub.service.EncryptionKeyCanaryMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping(
    path = "api/v1/key-usage",
    produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class KeyUsageController {

  private final CredentialVersionDataService credentialVersionDataService;
  private final EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;

  @Autowired
  public KeyUsageController(
      CredentialVersionDataService credentialVersionDataService,
      EncryptionKeyCanaryMapper encryptionKeyCanaryMapper) {
    this.credentialVersionDataService = credentialVersionDataService;
    this.encryptionKeyCanaryMapper = encryptionKeyCanaryMapper;
  }

  @RequestMapping(method = RequestMethod.GET, path = "")
  public ResponseEntity<Map> getKeyUsages() {
    List<UUID> canaryKeyInConfigUuids = encryptionKeyCanaryMapper.getKnownCanaryUuids();

    Long totalCredCount = credentialVersionDataService.count();
    Long credsNotEncryptedByActiveKey = credentialVersionDataService.countAllNotEncryptedByActiveKey();
    Long credsEncryptedByKnownKeys = credentialVersionDataService
        .countEncryptedWithKeyUuidIn(canaryKeyInConfigUuids);

    Long activeKeyCreds = totalCredCount - credsNotEncryptedByActiveKey;
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
