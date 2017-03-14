package io.pivotal.security.controller.v1;

import com.fasterxml.jackson.databind.JsonNode;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.config.JsonContextFactory;
import io.pivotal.security.helper.JsonHelper;
import org.hamcrest.Matchers;
import org.junit.runner.RunWith;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.HashMap;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
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
      subject = new VcapController(new JsonContextFactory());
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

            assertResponseJsonEquals(response, inputJsonString);
          });
        });

        describe("when credentials is somewhere unexpected", () -> {
          it("is ignored", () -> {
            String inputJsonString = "{" +
                "  \"VCAP_SERVICES\": {" +
                "    \"p-config-server\": [{" +
                "      \"foo\": {" +
                "        \"credentials\": {" +
                "          \"credhub-ref\": \"((/cred1))\"" +
                "         }" +
                "       }," +
                "      \"label\": \"p-config-server\"" +
                "    }]" +
                "  }" +
                "}";
            MockHttpServletResponse response = mockMvc.perform(post("/api/v1/vcap")
                .contentType(MediaType.APPLICATION_JSON).content(inputJsonString)
            ).andExpect(status().isOk()).andReturn().getResponse();

            assertResponseJsonEquals(response, inputJsonString);
          });
        });

        describe("when properties are not hashes", () -> {
          it("is ignored", () -> {
            String inputJsonString = "{" +
                "  \"VCAP_SERVICES\": {" +
                "    \"p-config-server\": [\"what is this?\"]" +
                "  }" +
                "}";
            MockHttpServletResponse response = mockMvc.perform(post("/api/v1/vcap")
                .contentType(MediaType.APPLICATION_JSON).content(inputJsonString)
            ).andExpect(status().isOk()).andReturn().getResponse();

            assertResponseJsonEquals(response, inputJsonString);
          });
        });

        describe("credentials is not a hash", () -> {
          it("is ignored", () -> {
            String inputJsonString = "{" +
                "  \"VCAP_SERVICES\": {" +
                "    \"p-config-server\": [{" +
                "      \"credentials\": \"moose\"," +
                "      \"label\": \"squirrel\"" +
                "    }]" +
                "  }" +
                "}";
            MockHttpServletResponse response = mockMvc.perform(post("/api/v1/vcap")
                .contentType(MediaType.APPLICATION_JSON).content(inputJsonString)
            ).andExpect(status().isOk()).andReturn().getResponse();

            assertResponseJsonEquals(response, inputJsonString);
          });
        });

        describe("when no properly formatted credentials section exists", () -> {
          it("is ignored", () -> {
            MockHttpServletResponse response = mockMvc.perform(post("/api/v1/vcap")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}")
            ).andExpect(status().isOk()).andReturn().getResponse();

            assertResponseJsonEquals(response, "{}");
          });
        });

        describe("when no VCAP_SERVICES key is present", () -> {
          it("is ignored", () -> {
            String inputJsonString = "{" +
                "  \"credentials\":{" +
                "    \"credhub-ref\":\"((/some/known/path))\"" +
                "  }" +
                "}";
            MockHttpServletResponse response = mockMvc.perform(post("/api/v1/vcap")
                .contentType(MediaType.APPLICATION_JSON)
                .content(inputJsonString)
            ).andExpect(status().isOk()).andReturn().getResponse();

            assertResponseJsonEquals(response, inputJsonString);
          });
        });

        describe("when VCAP_SERVICES is not an object", () -> {
          it("is ignored", () -> {
            String inputJsonString = "{" +
                "  \"VCAP_SERVICES\":[]" +
                "}";
            MockHttpServletResponse response = mockMvc.perform(post("/api/v1/vcap")
                .contentType(MediaType.APPLICATION_JSON)
                .content(inputJsonString)
            ).andExpect(status().isOk()).andReturn().getResponse();

            assertResponseJsonEquals(response, inputJsonString);
          });
        });

        describe("when the services properties are not arrays", () -> {
          it("is ignored", () -> {
            String inputJsonString = "{" +
                "  \"VCAP_SERVICES\": {" +
                "    \"p-config-server\": {" +
                "      \"credentials\": {" +
                "        \"credhub-ref\": \"((/cred1))\"" +
                "       }," +
                "      \"label\": \"p-config-server\"" +
                "    }" +
                "  }" +
                "}";
            MockHttpServletResponse response = mockMvc.perform(post("/api/v1/vcap")
                .contentType(MediaType.APPLICATION_JSON)
                .content(inputJsonString)
            ).andExpect(status().isOk()).andReturn().getResponse();

            assertResponseJsonEquals(response, inputJsonString);
          });
        });
      });
    });
  }

  private void assertResponseJsonEquals(MockHttpServletResponse response, String jsonString) throws Exception {
    JsonNode responseJson = JsonHelper.parse(response.getContentAsString());
    JsonNode inputJson = JsonHelper.parse(jsonString);

    assertThat(responseJson, equalTo(inputJson));
  }
}
