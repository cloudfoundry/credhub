package io.pivotal.security.controller.v1;

import com.google.common.collect.Lists;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.JsonCredential;
import io.pivotal.security.domain.ValueCredential;
import io.pivotal.security.helper.AuditingHelper;
import io.pivotal.security.repository.EventAuditRecordRepository;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.assertj.core.util.Maps;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
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

import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.helper.JsonTestHelper.parse;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
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

  @Autowired
  private RequestAuditRecordRepository requestAuditRecordRepository;

  @Autowired
  private EventAuditRecordRepository eventAuditRecordRepository;

  @SpyBean
  private CredentialDataService mockCredentialDataService;

  private MockMvc mockMvc;
  private AuditingHelper auditingHelper;

  @Before
  public void beforeEach() {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();

    auditingHelper = new AuditingHelper(requestAuditRecordRepository, eventAuditRecordRepository);
  }

  @Test
  public void POST_replacesTheCredHubRefWithTheCredentialValue() throws Exception {
    JsonCredential jsonCredential = mock(JsonCredential.class);
    doReturn(Maps.newHashMap("secret1", "secret1-value")).when(jsonCredential).getValue();
    when(jsonCredential.getName()).thenReturn("/cred1");

    JsonCredential jsonCredential1 = mock(JsonCredential.class);
    doReturn(Maps.newHashMap("secret2", "secret2-value")).when(jsonCredential1).getValue();
    when(jsonCredential1.getName()).thenReturn("/cred2");

    doReturn(
        jsonCredential
    ).when(mockCredentialDataService).findMostRecent("/cred1");

    doReturn(
        jsonCredential1
    ).when(mockCredentialDataService).findMostRecent("/cred2");

    mockMvc.perform(makeValidPostRequest()).andDo(print()).andExpect(status().isOk())
        .andExpect(jsonPath("$.pp-config-server[0].credentials.secret1")
            .value(equalTo("secret1-value")))
        .andExpect(jsonPath("$.pp-something-else[0].credentials.secret2")
            .value(equalTo("secret2-value")));
  }

  @Test
  public void POST_logsTheCredentialAccess() throws Exception {
    JsonCredential jsonCredential = mock(JsonCredential.class);
    doReturn(Maps.newHashMap("secret1", "secret1-value")).when(jsonCredential).getValue();
    when(jsonCredential.getName()).thenReturn("/cred1");

    JsonCredential jsonCredential1 = mock(JsonCredential.class);
    doReturn(Maps.newHashMap("secret2", "secret2-value")).when(jsonCredential1).getValue();
    when(jsonCredential1.getName()).thenReturn("/cred2");

    doReturn(
        jsonCredential
    ).when(mockCredentialDataService).findMostRecent("/cred1");

    doReturn(
        jsonCredential1
    ).when(mockCredentialDataService).findMostRecent("/cred2");

    mockMvc.perform(makeValidPostRequest()).andExpect(status().isOk());

    auditingHelper
        .verifyAuditing("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", "/api/v1/interpolate",
            200, Lists
                .newArrayList(
                    new EventAuditRecordParameters(CREDENTIAL_ACCESS, "/cred1"),
                    new EventAuditRecordParameters(CREDENTIAL_ACCESS, "/cred2")
                ));
  }

  @Test
  public void POST_whenAReferencedCredentialIsNotJsonType_throwsAnError() throws Exception {
    ValueCredential valueCredential = mock(ValueCredential.class);
    doReturn("something").when(valueCredential).getValue();

    doReturn(
        valueCredential
    ).when(mockCredentialDataService).findMostRecent("/cred1");

    String expectedMessage = "The credential '/cred1' is not the expected type. A credhub-ref credential must be of type 'JSON'.";

    mockMvc.perform(post("/api/v1/interpolate")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .contentType(MediaType.APPLICATION_JSON)
        .content(
            "{"
                + "    \"pp-config-server\": ["
                + "      {"
                + "        \"credentials\": {"
                + "          \"credhub-ref\": \"((/cred1))\""
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
    ).when(mockCredentialDataService).findMostRecent("/cred1");

    String expectedMessage = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";
    mockMvc.perform(post("/api/v1/interpolate")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .contentType(MediaType.APPLICATION_JSON)
        .content(
            "{"
                + "    \"pp-config-server\": ["
                + "      {"
                + "        \"credentials\": {"
                + "          \"credhub-ref\": \"((/cred1))\""
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
        + "        \"credhub-ref\": \"((/cred1))\""
        + "       },"
        + "      \"label\": \"pp-config-server\""
        + "    }]"
        + "}";
    MockHttpServletResponse response = mockMvc.perform(post("/api/v1/interpolate")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
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
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .contentType(MediaType.APPLICATION_JSON)
        .content(inputJsonString)
    )
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error", equalTo(expectedMessage)));
  }

  private MockHttpServletRequestBuilder makeValidPostRequest() {
    return post("/api/v1/interpolate")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .contentType(MediaType.APPLICATION_JSON)
        .content(
            "{"
                + "    \"pp-config-server\": ["
                + "      {"
                + "        \"credentials\": {"
                + "          \"credhub-ref\": \"((/cred1))\""
                + "        },"
                + "        \"label\": \"pp-config-server\""
                + "      }"
                + "    ],"
                + "    \"pp-something-else\": ["
                + "      {"
                + "        \"credentials\": {"
                + "          \"credhub-ref\": \"((/cred2))\""
                + "        },"
                + "        \"something\": [\"pp-config-server\"]"
                + "      }"
                + "    ]"
                + "  }"
        );
  }
}
