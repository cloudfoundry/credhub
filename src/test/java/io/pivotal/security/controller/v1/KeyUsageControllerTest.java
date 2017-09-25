package io.pivotal.security.controller.v1;

import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.data.EncryptionKeyCanaryDataService;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.util.DatabaseProfileResolver;
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
  CredentialDataService credentialDataService;
  EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;
  EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;

  @Before
  public void beforeEach() {
    credentialDataService = mock(CredentialDataService.class);
    encryptionKeyCanaryMapper = mock(EncryptionKeyCanaryMapper.class);
    encryptionKeyCanaryDataService = mock(EncryptionKeyCanaryDataService.class);
    final KeyUsageController keyUsageController = new KeyUsageController(credentialDataService,
        encryptionKeyCanaryMapper);

    mockMvc = MockMvcBuilders
        .standaloneSetup(keyUsageController)
        .alwaysDo(print())
        .build();
  }

  @Test
  public void getKeyUsages_getsKeyDistributionAcrossActiveInactiveAndUnknownEncryptionKeys()
      throws Exception {
    ArrayList<UUID> keysInConfigUuids = new ArrayList<UUID>() {{
      add(UUID.randomUUID());
      add(UUID.randomUUID());
    }};

    when(encryptionKeyCanaryMapper.getKnownCanaryUuids()).thenReturn(keysInConfigUuids);
    when(credentialDataService.count()).thenReturn(225L);
    when(credentialDataService.countAllNotEncryptedByActiveKey()).thenReturn(25L);
    when(credentialDataService.countEncryptedWithKeyUuidIn(keysInConfigUuids)).thenReturn(220L);

    mockMvc.perform(get("/api/v1/key-usage"))
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
        .andExpect(jsonPath("$.active_key").value(200))
        .andExpect(jsonPath("$.inactive_keys").value(20))
        .andExpect(jsonPath("$.unknown_keys").value(5));
  }

}
