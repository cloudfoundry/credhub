package io.pivotal.security.controller.v1;

import com.google.common.collect.ImmutableMap;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.data.EncryptionKeyCanaryDataService;
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
import java.util.stream.Collectors;

@RestController
@RequestMapping(
    path = "api/v1/key-usage",
    produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class KeyUsageController {

  private final CredentialDataService credentialDataService;
  private final EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;

  @Autowired
  public KeyUsageController(
      CredentialDataService credentialDataService,
      EncryptionKeyCanaryDataService encryptionKeyCanaryDataService) {
    this.credentialDataService = credentialDataService;
    this.encryptionKeyCanaryDataService = encryptionKeyCanaryDataService;
  }

  @RequestMapping(method = RequestMethod.GET, path = "")
  public ResponseEntity<Map> getKeyUsages() {
    List<UUID> canaryKeyUuids = encryptionKeyCanaryDataService.findAll().stream()
        .map(key -> key.getUuid())
        .collect(Collectors.toList());

    Long totalCredCount = credentialDataService.count();
    Long credsNotEncryptedByActiveKey = credentialDataService.countAllNotEncryptedByActiveKey();
    Long credsEncryptedByKnownKeys = credentialDataService
        .countEncryptedWithKeyUuidIn(canaryKeyUuids);

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
