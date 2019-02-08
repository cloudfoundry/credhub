package org.cloudfoundry.credhub.integration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import org.cloudfoundry.credhub.AuthConstants;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.DatabaseProfileResolver;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(profiles = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredhubTestApp.class)
@Transactional
public class UpdatingACredentialTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;
  private String passwordName;

  @Before
  public void beforeEach() {
    passwordName = "test-password";

    mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
      .apply(springSecurity())
      .build();
  }

  @Test
  public void post_shouldAllowTheCredentialToBeUpdated() throws Exception {
    String requestBody = "{"
      + "\"type\":\"password\","
      + "\"name\":\""
      + passwordName + "\","
      + "\"overwrite\":true"
      + "}";
    MvcResult result = mockMvc.perform(post("/api/v1/data")
      .header("Authorization", "Bearer "
        + AuthConstants.ALL_PERMISSIONS_TOKEN).accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content(requestBody)
    )
      .andExpect(status().is2xxSuccessful())
      .andReturn();

    JSONObject jsonObject = new JSONObject(result.getResponse().getContentAsString());
    final String firstPassword = jsonObject.getString("value");

    requestBody = "{"
      + "\"type\":\"password\","
      + "\"name\":\""
      + passwordName + "\","
      + "\"overwrite\":true"
      + "}";

    result = mockMvc.perform(post("/api/v1/data")
      .header("Authorization", "Bearer "
        + AuthConstants.ALL_PERMISSIONS_TOKEN).accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content(requestBody)
    )
      .andExpect(status().is2xxSuccessful())
      .andReturn();

    jsonObject = new JSONObject(result.getResponse().getContentAsString());
    final String lastPassword = jsonObject.getString("value");

    assertThat(firstPassword, is(not(equalTo(lastPassword))));
  }


  @Test
  public void put_shouldAllowTheCredentialToBeUpdated() throws Exception {
    String requestBody = "{"
      + "\"type\":\"password\","
      + "\"name\":\""
      + passwordName + "\",\"value\":\"ORIGINAL-VALUE\""
      + "}";
    mockMvc.perform(put("/api/v1/data")
      .header("Authorization", "Bearer "
        + AuthConstants.ALL_PERMISSIONS_TOKEN).accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content(requestBody)
    )
      .andExpect(status().is2xxSuccessful())
      .andExpect(jsonPath("$.value").value("ORIGINAL-VALUE"));

    requestBody = "{"
      + "\"type\":\"password\","
      + "\"name\":\""
      + passwordName + "\",\"value\":\"NEW-VALUE\""
      + "}";

    mockMvc.perform(put("/api/v1/data")
      .header("Authorization", "Bearer "
        + AuthConstants.ALL_PERMISSIONS_TOKEN).accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content(requestBody)
    )
      .andExpect(status().is2xxSuccessful())
      .andExpect(jsonPath("$.value").value("NEW-VALUE"));
  }
}
