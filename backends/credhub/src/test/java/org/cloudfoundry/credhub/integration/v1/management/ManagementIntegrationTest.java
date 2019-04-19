package org.cloudfoundry.credhub.integration.v1.management;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import org.cloudfoundry.credhub.AuthConstants;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.DatabaseProfileResolver;
import org.cloudfoundry.credhub.ManagementRegistry;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredhubTestApp.class)
@TestPropertySource(properties = "security.authorization.acls.enabled=false")
public class ManagementIntegrationTest {

  @Autowired
  private WebApplicationContext webApplicationContext;

  @Autowired
  private ManagementRegistry managementRegistry;

  private MockMvc mockMvc;

  @Before
  public void setUp() {
    mockMvc = MockMvcBuilders
      .webAppContextSetup(webApplicationContext)
      .apply(SecurityMockMvcConfigurers.springSecurity())
      .build();
  }

  @Test
  public void settingReadOnlyMode_updatesTheGlobalManagementVariable() throws Exception {
    MockHttpServletRequestBuilder request = post("/management")
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .header("content-type", APPLICATION_JSON)
      .content("{\"read_only_mode\":\"true\"}");
    mockMvc.perform(request).andExpect(status().isOk());

    assertThat(managementRegistry.getReadOnlyMode(), is(true));

    request = post("/management")
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .header("content-type", APPLICATION_JSON)
      .content("{\"read_only_mode\":\"false\"}");
    mockMvc.perform(request).andExpect(status().isOk());

    assertThat(managementRegistry.getReadOnlyMode(), is(false));
  }

  @Test
  public void gettingTheReadOnlyMode_returnsTheGlobalManagementVariable() throws Exception {
    managementRegistry.setReadOnlyMode(true);

    MockHttpServletRequestBuilder request = get("/management")
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);
    mockMvc.perform(request)
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.read_only_mode").value(true));

    managementRegistry.setReadOnlyMode(false);

    request = get("/management")
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);
    mockMvc.perform(request)
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.read_only_mode").value(false));
  }

  @Test
  public void providingAnInvalidRequestBody_returns400() throws Exception {
    final MockHttpServletRequestBuilder request = post("/management")
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .header("content-type", APPLICATION_JSON)
      .content("{\"read_only_mode\":\"pizza\"}");
    mockMvc.perform(request).andExpect(status().isBadRequest());
  }
}
