package io.pivotal.security.controller.v1.secret;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedSshSecret;
import io.pivotal.security.helper.TestConstants;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.json.JSONObject;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
@ActiveProfiles(profiles = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class SecretsControllerSshSetTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @SpyBean
  SecretDataService secretDataService;

  private MockMvc mockMvc;

  private final String secretName = "/my-namespace/secretForSetTest/secret-name";

  private ResultActions response;

  {
    wireAndUnwire(this);


    beforeEach(() -> {
      mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
    });

    describe("setting SSH keys", () -> {
      describe("when required values are passed", () -> {
        beforeEach(() -> {
          JSONObject obj = new JSONObject();
          obj.put("public_key", TestConstants.PUBLIC_KEY_OF_LENGTH_4096_WITH_COMMENT);
          obj.put("private_key", TestConstants.PRIVATE_KEY_OF_LENGTH_4096);

          final MockHttpServletRequestBuilder put = put("/api/v1/data")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{" +
                  "  \"type\":\"ssh\"," +
                  "  \"name\":\"" + secretName + "\"," +
                  "  \"value\":" + obj.toString() +
                  "}");

          response = mockMvc.perform(put);
        });

        it("returns the secret as json", () -> {
          NamedSshSecret expected = (NamedSshSecret) secretDataService.findMostRecent(secretName);

          assertThat(expected.getPrivateKey(), equalTo(TestConstants.PRIVATE_KEY_OF_LENGTH_4096));

          response.andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.type").value("ssh"))
              .andExpect(jsonPath("$.value.public_key").value(TestConstants.PUBLIC_KEY_OF_LENGTH_4096_WITH_COMMENT))
              .andExpect(jsonPath("$.value.private_key").value(TestConstants.PRIVATE_KEY_OF_LENGTH_4096))
              .andExpect(jsonPath("$.id").value(expected.getUuid().toString()));
        });
      });

      describe("when the value contains unknown keys", () -> {
        it("should return an error", () -> {
          final MockHttpServletRequestBuilder put = put("/api/v1/data")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{" +
                  "  \"type\":\"ssh\"," +
                  "  \"name\":\"" + secretName + "\"," +
                  "  \"value\": {" +
                  "    \"foo\":\"bar\"" +
                  "  }" +
                  "}");
          final String errorMessage = "The request includes an unrecognized parameter 'foo'. Please update or remove this parameter and retry your request.";
          mockMvc.perform(put)
              .andExpect(status().isBadRequest())
              .andExpect(jsonPath("$.error").value(errorMessage));
        });
      });

      describe("when all values are empty", () -> {
        it("should return an error message", () -> {
          final MockHttpServletRequestBuilder put = put("/api/v1/data")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{" +
                  "  \"type\":\"ssh\"," +
                  "  \"name\":\"" + secretName + "\"," +
                  "  \"value\": { \"public_key\":\"\", \"private_key\":\"\" }" +
                  "}");
          final String errorMessage = "At least one key value must be set. Please validate your input and retry your request.";
          mockMvc.perform(put)
              .andExpect(status().isBadRequest())
              .andExpect(jsonPath("$.error").value(errorMessage));
        });
      });
    });
  }
}
