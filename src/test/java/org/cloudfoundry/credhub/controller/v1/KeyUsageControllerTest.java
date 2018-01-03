package org.cloudfoundry.credhub.controller.v1;

import org.cloudfoundry.credhub.data.CredentialVersionDataService;
import org.cloudfoundry.credhub.data.EncryptionKeyCanaryDataService;
import org.cloudfoundry.credhub.service.EncryptionKeyCanaryMapper;
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

import java.util.ArrayList;
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
  EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;

  @Before
  public void beforeEach() {
    credentialVersionDataService = mock(CredentialVersionDataService.class);
    encryptionKeyCanaryMapper = mock(EncryptionKeyCanaryMapper.class);
    encryptionKeyCanaryDataService = mock(EncryptionKeyCanaryDataService.class);
    final KeyUsageController keyUsageController = new KeyUsageController(credentialVersionDataService,
        encryptionKeyCanaryMapper);

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
    ArrayList<UUID> keysInConfigUuids = new ArrayList<UUID>() {{
      add(activeKey);
      add(knownKey);
    }};

    HashMap<UUID, Long> countByEncryptionKey = new HashMap<>();
    countByEncryptionKey.put(activeKey, 200L);
    countByEncryptionKey.put(knownKey, 10L);
    countByEncryptionKey.put(unknownKey, 5L);

    when(encryptionKeyCanaryMapper.getKnownCanaryUuids()).thenReturn(keysInConfigUuids);
    when(encryptionKeyCanaryMapper.getActiveUuid()).thenReturn(activeKey);
    when(credentialVersionDataService.countByEncryptionKey()).thenReturn(countByEncryptionKey);

    mockMvc.perform(get("/api/v1/key-usage"))
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
        .andExpect(jsonPath("$.active_key").value(200))
        .andExpect(jsonPath("$.inactive_keys").value(10))
        .andExpect(jsonPath("$.unknown_keys").value(5));
  }

}
