package org.cloudfoundry.credhub.integration;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.cloudfoundry.credhub.helpers.RequestHelper.generatePassword;
import static org.cloudfoundry.credhub.utils.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.cloudfoundry.credhub.utils.AuthConstants.USER_A_TOKEN;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredhubTestApp.class)
@Transactional
@TestPropertySource(properties = "security.authorization.acls.enabled=false")
public class CredentialFindTestNoAcls {

  @Autowired
  private WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;

  @BeforeEach
  public void beforeEach() {
    mockMvc = MockMvcBuilders
      .webAppContextSetup(webApplicationContext)
      .apply(springSecurity())
      .build();
  }

  @Test
  public void findCredentials_byPath_returnsAllCredentialsWhenAclsAreDisabled() throws Exception {
    generateCredentials();

    final MockHttpServletRequestBuilder request = get("/api/v1/data?path=/")
      .header("Authorization", "Bearer " + USER_A_TOKEN)
      .accept(APPLICATION_JSON);

    mockMvc.perform(request).andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.credentials", hasSize(5)));
  }

  private void generateCredentials() throws Exception {
    final List<String> names = Arrays.asList(new String[]{"/path/to/credentialA", "/path/something",
      "/path/to/credentialB", "/other_path/credentialC", "/another/credentialC"});

    for (final String name : names) {
      generatePassword(mockMvc, name, true, 20, ALL_PERMISSIONS_TOKEN);
    }
  }
}
