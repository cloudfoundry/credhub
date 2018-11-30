package org.cloudfoundry.credhub.controller.v1;

import java.io.IOException;
import java.util.Arrays;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.data.CredentialVersionDataService;
import org.cloudfoundry.credhub.domain.JsonCredentialVersion;
import org.cloudfoundry.credhub.domain.ValueCredentialVersion;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.cloudfoundry.credhub.helper.JsonTestHelper.parse;
import static org.cloudfoundry.credhub.util.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class InterpolationControllerTest {
  @Autowired
  private WebApplicationContext webApplicationContext;

  @SpyBean
  private CredentialVersionDataService mockCredentialVersionDataService;

  private MockMvc mockMvc;

  @Before
  public void beforeEach() {
    mockMvc = MockMvcBuilders
      .webAppContextSetup(webApplicationContext)
      .apply(springSecurity())
      .build();
  }

  @Test
  public void POST_replacesTheCredHubRefWithTheCredentialValue() throws Exception {
    String credJson1 = "{\"secret1\":\"secret1-value\"}";
    JsonNode jsonNode1;
    try {
      jsonNode1 = new ObjectMapper().readTree(credJson1);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    JsonCredentialVersion jsonCredential1 = mock(JsonCredentialVersion.class);
    doReturn(jsonNode1).when(jsonCredential1).getValue();
    when(jsonCredential1.getName()).thenReturn("/cred1");
    when(jsonCredential1.getUuid()).thenReturn(UUID.randomUUID());

    String credJson2 = "{\"secret2\":\"secret2-value\"}";
    JsonNode jsonNode2;
    try {
      jsonNode2 = new ObjectMapper().readTree(credJson2);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    JsonCredentialVersion jsonCredential2 = mock(JsonCredentialVersion.class);
    doReturn(jsonNode2).when(jsonCredential2).getValue();
    when(jsonCredential2.getName()).thenReturn("/cred2");
    when(jsonCredential2.getUuid()).thenReturn(UUID.randomUUID());

    doReturn(
      Arrays.asList(jsonCredential1)
    ).when(mockCredentialVersionDataService).findNByName("/cred1", 1);

    doReturn(
      Arrays.asList(jsonCredential2)
    ).when(mockCredentialVersionDataService).findNByName("/cred2", 1);

    mockMvc.perform(makeValidPostRequest()).andDo(print()).andExpect(status().isOk())
      .andExpect(jsonPath("$.pp-config-server[0].credentials.secret1")
        .value(equalTo("secret1-value")))
      .andExpect(jsonPath("$.pp-something-else[0].credentials.secret2")
        .value(equalTo("secret2-value")));
  }

  @Test
  public void POST_whenAReferencedCredentialIsNotJsonType_throwsAnError() throws Exception {
    ValueCredentialVersion valueCredential = mock(ValueCredentialVersion.class);
    doReturn("something").when(valueCredential).getValue();
    doReturn(UUID.randomUUID()).when(valueCredential).getUuid();

    doReturn(
      Arrays.asList(valueCredential)
    ).when(mockCredentialVersionDataService).findNByName("/cred1", 1);

    String expectedMessage = "The credential '/cred1' is not the expected type. A credhub-ref credential must be of type 'JSON'.";

    mockMvc.perform(post("/api/v1/interpolate")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .contentType(MediaType.APPLICATION_JSON)
      .content(
        "{"
          + "    \"pp-config-server\": ["
          + "      {"
          + "        \"credentials\": {"
          + "          \"credhub-ref\": \"/cred1\""
          + "        },"
          + "        \"label\": \"pp-config-server\""
          + "      }"
          + "    ]"
          + "}"
      )
    ).andExpect(status().is4xxClientError())
      .andExpect(jsonPath("$.error", equalTo(expectedMessage)));
  }

  @Test
  public void POST_whenAReferencedCredentialDoesNotExist_throwsAnError() throws Exception {
    doReturn(
      null
    ).when(mockCredentialVersionDataService).findMostRecent("/cred1");

    String expectedMessage = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";
    mockMvc.perform(post("/api/v1/interpolate")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .contentType(MediaType.APPLICATION_JSON)
      .content(
        "{"
          + "    \"pp-config-server\": ["
          + "      {"
          + "        \"credentials\": {"
          + "          \"credhub-ref\": \"/cred1\""
          + "        },"
          + "        \"label\": \"pp-config-server\""
          + "      }"
          + "    ]"
          + "}"
      )
    ).andExpect(status().is4xxClientError())
      .andExpect(jsonPath("$.error", equalTo(expectedMessage)));
  }

  @Test
  public void POST_whenTheServicesPropertiesDoNotHaveCredentials_doesNotInterpolateThem() throws Exception {
    String inputJsonString = "{"
      + "    \"pp-config-server\": [{"
      + "      \"blah\": {"
      + "        \"credhub-ref\": \"/cred1\""
      + "       },"
      + "      \"label\": \"pp-config-server\""
      + "    }]"
      + "}";
    MockHttpServletResponse response = mockMvc.perform(post("/api/v1/interpolate")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .contentType(MediaType.APPLICATION_JSON)
      .content(inputJsonString)
    ).andExpect(status().isOk()).andReturn().getResponse();

    assertThat(parse(response.getContentAsString()), equalTo(parse(inputJsonString)));
  }

  @Test
  public void POST_whenTheRequestBodyIsNotJSON_throwsAnError() throws Exception {
    String inputJsonString = "</xml?>";
    String expectedMessage = "The request could not be fulfilled because the request path or body did not meet expectation. Please check the documentation for required formatting and retry your request.";

    mockMvc.perform(post("/api/v1/interpolate")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .contentType(MediaType.APPLICATION_JSON)
      .content(inputJsonString)
    )
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", equalTo(expectedMessage)));
  }

  private MockHttpServletRequestBuilder makeValidPostRequest() {
    return post("/api/v1/interpolate")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .contentType(MediaType.APPLICATION_JSON)
      .content(
        "{"
          + "    \"pp-config-server\": ["
          + "      {"
          + "        \"credentials\": {"
          + "          \"credhub-ref\": \"/cred1\""
          + "        },"
          + "        \"label\": \"pp-config-server\""
          + "      }"
          + "    ],"
          + "    \"pp-something-else\": ["
          + "      {"
          + "        \"credentials\": {"
          + "          \"credhub-ref\": \"/cred2\""
          + "        },"
          + "        \"something\": [\"pp-config-server\"]"
          + "      }"
          + "    ]"
          + "  }"
      );
  }
}
