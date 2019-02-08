package org.cloudfoundry.credhub.integration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import org.cloudfoundry.credhub.AuthConstants;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.DatabaseProfileResolver;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.hamcrest.core.IsAnything.anything;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = CredhubTestApp.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@Transactional
public class VersionEndpointTest {

  @Autowired
  private WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;

  @Test
  public void GET_whenTheUserIsAuthenticated_returnsTheServerVersion() throws Exception {
    mockMvc = MockMvcBuilders
      .webAppContextSetup(webApplicationContext)
      .apply(springSecurity())
      .build();

    final MockHttpServletRequestBuilder getRequest = get(
      "/version")
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN);
    mockMvc.perform(getRequest)
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.version", anything()));
  }

  @Test
  public void GET_whenTheUserIsNotAuthenticated_returnsAnError() throws Exception {
    mockMvc = MockMvcBuilders
      .webAppContextSetup(webApplicationContext)
      .apply(springSecurity())
      .build();

    final MockHttpServletRequestBuilder getRequest = get(
      "/version");
    mockMvc.perform(getRequest)
      .andExpect(status().isUnauthorized());
  }
}
