package io.pivotal.security.controller.v1;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonHelper.parse;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedJsonSecret;
import io.pivotal.security.domain.NamedValueSecret;
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
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class VcapControllerTest {

  @Autowired
  WebApplicationContext webApplicationContext;
  @SpyBean
  SecretDataService mockSecretDataService;
  private MockMvc mockMvc;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      mockMvc = MockMvcBuilders
          .webAppContextSetup(webApplicationContext)
          .apply(springSecurity())
          .build();
    });

    describe("/vcap", () -> {
      describe("#POST", () -> {
        describe("when properly formatted credentials section is found", () -> {
          it("should replace the credhub-ref element with something else", () -> {
            NamedJsonSecret jsonSecret1 = mock(NamedJsonSecret.class);
            doReturn(Maps.newHashMap("secret1", "secret1-value")).when(jsonSecret1).getValue();

            NamedJsonSecret jsonSecret2 = mock(NamedJsonSecret.class);
            doReturn(Maps.newHashMap("secret2", "secret2-value")).when(jsonSecret2).getValue();

            doReturn(
                jsonSecret1
            ).when(mockSecretDataService).findMostRecent("/cred1");

            doReturn(
                jsonSecret2
            ).when(mockSecretDataService).findMostRecent("/cred2");

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
                )
            ).andExpect(status().isOk())
                .andExpect(jsonPath("$.VCAP_SERVICES.pp-config-server[0].credentials.secret1")
                    .value(equalTo("secret1-value")))
                .andExpect(jsonPath("$.VCAP_SERVICES.pp-something-else[0].credentials.secret2")
                    .value(equalTo("secret2-value")));
          });
        });

        describe("when the requested credential is not a NamedJsonSecret", () -> {
          it("should return an error", () -> {
            NamedValueSecret valueSecret = mock(NamedValueSecret.class);
            doReturn("something").when(valueSecret).getValue();

            doReturn(
                valueSecret
            ).when(mockSecretDataService).findMostRecent("/cred1");

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
            ).when(mockSecretDataService).findMostRecent("/cred1");

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
