package io.pivotal.security.controller.v1;

import com.google.common.collect.Lists;
import com.greghaskins.spectrum.Spectrum;
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
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.helper.JsonHelper.parse;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
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

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class VcapControllerTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @Autowired
  RequestAuditRecordRepository requestAuditRecordRepository;

  @Autowired
  EventAuditRecordRepository eventAuditRecordRepository;

  @SpyBean
  CredentialDataService mockCredentialDataService;
  private MockMvc mockMvc;
  private AuditingHelper auditingHelper;
  MockHttpServletRequestBuilder post;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      mockMvc = MockMvcBuilders
          .webAppContextSetup(webApplicationContext)
          .apply(springSecurity())
          .build();

      auditingHelper = new AuditingHelper(requestAuditRecordRepository, eventAuditRecordRepository);
    });

    describe("/vcap", () -> {
      describe("#POST", () -> {
        beforeEach(() -> {
          post = post("/api/v1/vcap")
                  .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                  .contentType(MediaType.APPLICATION_JSON)
                  .content(
                      "{"
                          + "  \"VCAP_SERVICES\": {"
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
                          + "}"
                  );
            });

        describe("when properly formatted credentials section is found", () -> {
          it("should replace the credhub-ref element with something else", () -> {
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

            mockMvc.perform(post).andDo(print()).andExpect(status().isOk())
                .andExpect(jsonPath("$.VCAP_SERVICES.pp-config-server[0].credentials.secret1")
                    .value(equalTo("secret1-value")))
                .andExpect(jsonPath("$.VCAP_SERVICES.pp-something-else[0].credentials.secret2")
                    .value(equalTo("secret2-value")));
          });

          it("logs the credential access", () -> {
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

            mockMvc.perform(post).andExpect(status().isOk());

            auditingHelper.verifyAuditing("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", "/api/v1/vcap", 200, Lists
                .newArrayList(
                    new EventAuditRecordParameters(CREDENTIAL_ACCESS, "/cred1"),
                    new EventAuditRecordParameters(CREDENTIAL_ACCESS, "/cred2")
                ));
          });
        });

        describe("when the requested credential is not a JsonCredentialValue", () -> {
          it("should return an error", () -> {
            ValueCredential valueCredential = mock(ValueCredential.class);
            doReturn("something").when(valueCredential).getValue();

            doReturn(
                valueCredential
            ).when(mockCredentialDataService).findMostRecent("/cred1");

            mockMvc.perform(post("/api/v1/vcap")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    "{"
                        + "  \"VCAP_SERVICES\": {"
                        + "    \"pp-config-server\": ["
                        + "      {"
                        + "        \"credentials\": {"
                        + "          \"credhub-ref\": \"((/cred1))\""
                        + "        },"
                        + "        \"label\": \"pp-config-server\""
                        + "      }"
                        + "    ]"
                        + "  }"
                        + "}"
                )
            ).andExpect(status().is4xxClientError())
                .andExpect(jsonPath("$.error", equalTo(
                    "The credential '/cred1' is not the expected type. "
                        + "A credhub-ref credential must be of type 'JSON'.")));
          });
        });

        describe("when the requested credential is not accessible", () -> {
          it("should return an error", () -> {
            doReturn(
                null
            ).when(mockCredentialDataService).findMostRecent("/cred1");

            mockMvc.perform(post("/api/v1/vcap")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    "{"
                        + "  \"VCAP_SERVICES\": {"
                        + "    \"pp-config-server\": ["
                        + "      {"
                        + "        \"credentials\": {"
                        + "          \"credhub-ref\": \"((/cred1))\""
                        + "        },"
                        + "        \"label\": \"pp-config-server\""
                        + "      }"
                        + "    ]"
                        + "  }"
                        + "}"
                )
            ).andExpect(status().is4xxClientError())
                .andExpect(jsonPath("$.error", equalTo(
                    "The request could not be completed because a reference credential"
                        + " could not be accessed. Please update and retry your request.")));
          });
        });

        describe("when the services properties do not have credentials", () -> {
          it("is ignored", () -> {
            String inputJsonString = "{"
                + "  \"VCAP_SERVICES\": {"
                + "    \"pp-config-server\": [{"
                + "      \"blah\": {"
                + "        \"credhub-ref\": \"((/cred1))\""
                + "       },"
                + "      \"label\": \"pp-config-server\""
                + "    }]"
                + "  }"
                + "}";
            MockHttpServletResponse response = mockMvc.perform(post("/api/v1/vcap")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .content(inputJsonString)
            ).andExpect(status().isOk()).andReturn().getResponse();

            assertThat(parse(response.getContentAsString()), equalTo(parse(inputJsonString)));
          });
        });

        describe("when it's not even json", () -> {
          it("should fail with \"Bad Request\"", () -> {
            String inputJsonString = "</xml?>";
            mockMvc.perform(post("/api/v1/vcap")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .content(inputJsonString)
            ).andExpect(status().isBadRequest());
          });
        });
      });
    });
  }
}
