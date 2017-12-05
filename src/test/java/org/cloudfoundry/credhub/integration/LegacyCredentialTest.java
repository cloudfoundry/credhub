package org.cloudfoundry.credhub.integration;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.data.CredentialVersionDataService;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.domain.ValueCredentialVersion;
import org.cloudfoundry.credhub.entity.ValueCredentialVersionData;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.cloudfoundry.credhub.util.AuthConstants;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@Transactional
@TestPropertySource(properties = "security.authorization.acls.enabled=true")
public class LegacyCredentialTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @Autowired
  CredentialVersionDataService credentialVersionDataService;

  @Autowired
  Encryptor encryptor;

  private MockMvc mockMvc;
  private String CREDENTIAL_NAME;

  @Before
  public void setup() throws Exception {
    CREDENTIAL_NAME = "/bob";
    ValueCredentialVersionData valueCredentialData = new ValueCredentialVersionData(CREDENTIAL_NAME);
    ValueCredentialVersion noAclsSecret = new ValueCredentialVersion(valueCredentialData);
    noAclsSecret.setEncryptor(encryptor);
    noAclsSecret.setValue("bob's value");

    credentialVersionDataService.save(noAclsSecret);
    mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();
  }

  @Test
  public void GET_byCredentialName_whenTheCredentialHasNoAclsSet_returnsTheCredential()
      throws Exception {
    final MockHttpServletRequestBuilder get = get("/api/v1/data?name=" + CREDENTIAL_NAME)
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN);
    mockMvc.perform(get)
        .andDo(print())
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data[0].type", equalTo("value")))
        .andExpect(jsonPath("$.data[0].name", equalTo(CREDENTIAL_NAME)));
  }
}
