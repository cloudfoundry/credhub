package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedJsonSecret;
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

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonHelper.parse;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class VcapControllerTest {
  private MockMvc mockMvc;

  @Autowired
  WebApplicationContext webApplicationContext;

  @SpyBean
  SecretDataService mockSecretDataService;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
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
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    "{" +
                    "  \"VCAP_SERVICES\": {" +
                    "    \"p-config-server\": [" +
                    "      {" +
                    "        \"credentials\": {" +
                    "          \"credhub-ref\": \"((/cred1))\"" +
                    "        }," +
                    "        \"label\": \"p-config-server\"" +
                    "      }" +
                    "    ]," +
                    "    \"p-something-else\": [" +
                    "      {" +
                    "        \"credentials\": {" +
                    "          \"credhub-ref\": \"((/cred2))\"" +
                    "        }," +
                    "        \"something\": [\"p-config-server\"]" +
                    "      }" +
                    "    ]" +
                    "  }" +
                    "}"
                )
            ).andExpect(status().isOk())
                .andExpect(jsonPath("$.VCAP_SERVICES.p-config-server[0].credentials.secret1").value(equalTo("secret1-value")))
                .andExpect(jsonPath("$.VCAP_SERVICES.p-something-else[0].credentials.secret2").value(equalTo("secret2-value")));
          });
        });

        describe("when the services properties do not have credentials", () -> {
          it("is ignored", () -> {
            String inputJsonString = "{" +
                "  \"VCAP_SERVICES\": {" +
                "    \"p-config-server\": [{" +
                "      \"blah\": {" +
                "        \"credhub-ref\": \"((/cred1))\"" +
                "       }," +
                "      \"label\": \"p-config-server\"" +
                "    }]" +
                "  }" +
                "}";
            MockHttpServletResponse response = mockMvc.perform(post("/api/v1/vcap")
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
                .contentType(MediaType.APPLICATION_JSON)
                .content(inputJsonString)
            ).andExpect(status().isBadRequest());
          });
        });
      });
    });
  }
}
