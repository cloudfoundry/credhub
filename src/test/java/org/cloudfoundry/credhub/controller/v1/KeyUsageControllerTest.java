package org.cloudfoundry.credhub.controller.v1;

import org.cloudfoundry.credhub.data.CredentialVersionDataService;
import org.cloudfoundry.credhub.data.EncryptionKeyCanaryDataService;
import org.cloudfoundry.credhub.service.EncryptionKey;
import org.cloudfoundry.credhub.service.EncryptionKeySet;
import org.cloudfoundry.credhub.service.EncryptionService;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.security.Key;
import java.util.HashMap;
import java.util.UUID;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(JUnit4.class)
@SpringBootTest
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
public class KeyUsageControllerTest {

  private MockMvc mockMvc;
  CredentialVersionDataService credentialVersionDataService;
  EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;
  EncryptionKeySet keySet;

  @Before
  public void beforeEach() {
    credentialVersionDataService = mock(CredentialVersionDataService.class);
    keySet = new EncryptionKeySet();
    encryptionKeyCanaryDataService = mock(EncryptionKeyCanaryDataService.class);
    final KeyUsageController keyUsageController = new KeyUsageController(credentialVersionDataService,
        keySet);

    mockMvc = MockMvcBuilders
        .standaloneSetup(keyUsageController)
        .alwaysDo(print())
        .build();
  }

  @Test
  public void getKeyUsages_getsKeyDistributionAcrossActiveInactiveAndUnknownEncryptionKeys()
      throws Exception {
    final UUID activeKey = UUID.randomUUID();
    final UUID knownKey = UUID.randomUUID();
    final UUID unknownKey = UUID.randomUUID();

    HashMap<UUID, Long> countByEncryptionKey = new HashMap<>();
    countByEncryptionKey.put(activeKey, 200L);
    countByEncryptionKey.put(knownKey, 10L);
    countByEncryptionKey.put(unknownKey, 5L);

    keySet.add(new EncryptionKey(mock(EncryptionService.class), activeKey, mock(Key.class)));
    keySet.add(new EncryptionKey(mock(EncryptionService.class), knownKey, mock(Key.class)));
    keySet.setActive(activeKey);
    when(credentialVersionDataService.countByEncryptionKey()).thenReturn(countByEncryptionKey);

    mockMvc.perform(get("/api/v1/key-usage"))
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
        .andExpect(jsonPath("$.active_key").value(200))
        .andExpect(jsonPath("$.inactive_keys").value(10))
        .andExpect(jsonPath("$.unknown_keys").value(5));
  }

}
