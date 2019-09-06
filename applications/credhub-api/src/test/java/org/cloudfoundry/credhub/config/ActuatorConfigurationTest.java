package org.cloudfoundry.credhub.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import org.cloudfoundry.credhub.CredHubApp;
import org.cloudfoundry.credhub.DatabaseProfileResolver;
import org.cloudfoundry.credhub.auth.ActuatorPortFilter;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredHubApp.class, properties = {"management.server.port=80"})
public class ActuatorConfigurationTest {

  @Autowired
  private WebApplicationContext applicationContext;

  @Autowired
  private ActuatorPortFilter actuatorPortFilter;

  private MockMvc mockMvc;

  @Before
  public void beforeEach() {
    mockMvc = MockMvcBuilders
      .webAppContextSetup(applicationContext)
      .addFilters(actuatorPortFilter)
      .apply(springSecurity())
      .build();
  }

  @Test
  public void actuatorPortFilter_returns404_forRequestsToNonHealthEndpoint() throws Exception {
    final MockHttpServletRequestBuilder get = get("/api/v1/interpolate")
      .accept(MediaType.APPLICATION_JSON)
      .contentType(MediaType.APPLICATION_JSON);

    mockMvc.perform(get)
      .andExpect(status().isNotFound());
  }

  @Test
  public void actuatorPortFilter_returns200_forRequestsToHealthEndpoint() throws Exception {
    final MockHttpServletRequestBuilder get = get("/health")
      .accept(MediaType.APPLICATION_JSON)
      .contentType(MediaType.APPLICATION_JSON);

    mockMvc.perform(get)
      .andExpect(status().isOk());
  }

}
