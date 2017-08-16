package io.pivotal.security.controller.v1;

import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.data.EncryptionKeyCanaryDataService;
import io.pivotal.security.entity.EncryptionKeyCanary;
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

import java.util.Arrays;
import java.util.List;

import static org.mockito.Matchers.anyList;
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

  @Before
  public void beforeEach() {
    credentialDataService = mock(CredentialDataService.class);
    encryptionKeyCanaryDataService = mock(EncryptionKeyCanaryDataService.class);
    final KeyUsageController keyUsageController = new KeyUsageController(credentialDataService,
        encryptionKeyCanaryDataService);

    mockMvc = MockMvcBuilders
        .standaloneSetup(keyUsageController)
        .alwaysDo(print())
        .build();
  }

  @Test
  public void getKeyUsages_getsKeyDistributionAcrossActiveInactiveAndUnknownEncryptionKeys()
      throws Exception {
    List<EncryptionKeyCanary> canaries = Arrays
        .asList(new EncryptionKeyCanary(), new EncryptionKeyCanary());

    when(encryptionKeyCanaryDataService.findAll()).thenReturn(
        canaries);
    when(credentialDataService.count()).thenReturn(225L);
    when(credentialDataService.countAllNotEncryptedByActiveKey()).thenReturn(25L);
    when(credentialDataService.countEncryptedWithKeyUuidIn(anyList())).thenReturn(220L);

    mockMvc.perform(get("/api/v1/key-usage"))
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
        .andExpect(jsonPath("$.active_key").value(200))
        .andExpect(jsonPath("$.inactive_keys").value(20))
        .andExpect(jsonPath("$.unknown_keys").value(5));
  }

}
