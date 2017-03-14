package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.config.JsonContextFactory;
import io.pivotal.security.service.JsonInterpolationService;
import org.junit.runner.RunWith;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.fdescribe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonHelper.parse;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.isEmptyString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
public class VcapControllerTest {
  private VcapController subject;
  private MockMvc mockMvc;

  {
    beforeEach(() -> {
      subject = new VcapController(new JsonInterpolationService(new JsonContextFactory()));
      mockMvc = MockMvcBuilders.standaloneSetup(subject)
          .build();
    });

    describe("/vcap", () -> {
      describe("#POST", () -> {
        describe("when properly formatted credentials section is found", () -> {
          it("should replace the credhub-ref element with something else", () -> {
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
                    "      }," +
                    "      {" +
                    "        \"credentials\": {" +
                    "          \"credhub-ref\": \"((/cred2))\"" +
                    "        }" +
                    "      }" +
                    "    ]," +
                    "    \"p-something-else\": [" +
                    "      {" +
                    "        \"credentials\": {" +
                    "          \"credhub-ref\": \"((/cred3))\"" +
                    "        }," +
                    "        \"something\": [\"p-config-server\"]" +
                    "      }" +
                    "    ]" +
                    "  }" +
                    "}"
                )
            ).andExpect(status().isOk())
                .andExpect(jsonPath("$.VCAP_SERVICES.p-config-server[0].credentials").value(not(containsString("credhub-ref"))))
                .andExpect(jsonPath("$.VCAP_SERVICES.p-config-server[0].credentials").value(not(isEmptyString())))
                .andExpect(jsonPath("$.VCAP_SERVICES.p-config-server[1].credentials").value(not(containsString("credhub-ref"))))
                .andExpect(jsonPath("$.VCAP_SERVICES.p-config-server[1].credentials").value(not(isEmptyString())))
                .andExpect(jsonPath("$.VCAP_SERVICES.p-something-else[0].credentials").value(not(containsString("credhub-ref"))))
                .andExpect(jsonPath("$.VCAP_SERVICES.p-something-else[0].credentials").value(not(isEmptyString())));
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
