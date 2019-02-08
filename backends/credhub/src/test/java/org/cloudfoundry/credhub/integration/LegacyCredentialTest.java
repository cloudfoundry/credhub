package org.cloudfoundry.credhub.integration;

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

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.DatabaseProfileResolver;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.domain.ValueCredentialVersion;
import org.cloudfoundry.credhub.entity.ValueCredentialVersionData;
import org.cloudfoundry.credhub.services.CredentialVersionDataService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.cloudfoundry.credhub.AuthConstants.NO_PERMISSIONS_TOKEN;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = CredhubTestApp.class)
@ActiveProfiles(
  value = {
    "unit-test",
    "unit-test-permissions",
  },
  resolver = DatabaseProfileResolver.class
)
@Transactional
@TestPropertySource(properties = "security.authorization.acls.enabled=true")
@SuppressFBWarnings(
  value = "SS_SHOULD_BE_STATIC",
  justification = "Test files generally don't need static fields."
)
public class LegacyCredentialTest {
  private final String CREDENTIAL_NAME = "/some-cred";
  @Autowired
  WebApplicationContext webApplicationContext;
  @Autowired
  CredentialVersionDataService credentialVersionDataService;
  @Autowired
  Encryptor encryptor;
  private MockMvc mockMvc;

  @Before
  public void setup() {
    final ValueCredentialVersionData valueCredentialData = new ValueCredentialVersionData(CREDENTIAL_NAME);
    final ValueCredentialVersion noAclsSecret = new ValueCredentialVersion(valueCredentialData);
    noAclsSecret.setEncryptor(encryptor);
    noAclsSecret.setValue("some value");

    credentialVersionDataService.save(noAclsSecret);
    mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
      .apply(springSecurity())
      .build();
  }

  @Test
  public void GET_byCredentialName_whenTheCredentialHasNoAclsSet_ReturnsNotFound() throws Exception {
    final MockHttpServletRequestBuilder get = get("/api/v1/data?name=" + CREDENTIAL_NAME)
      .header("Authorization", "Bearer " + NO_PERMISSIONS_TOKEN);
    mockMvc.perform(get)
      .andDo(print())
      .andExpect(status().isNotFound());
  }
}
