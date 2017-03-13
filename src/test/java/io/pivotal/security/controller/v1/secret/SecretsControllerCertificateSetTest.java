package io.pivotal.security.controller.v1.secret;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.util.DatabaseProfileResolver;
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
public class SecretsControllerCertificateSetTest {

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

    describe("setting certificates", () -> {
      describe("when required values are passed", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder put = put("/api/v1/data")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{" +
                  "  \"type\":\"certificate\"," +
                  "  \"name\":\"" + secretName + "\"," +
                  "  \"value\": {" +
                  "    \"ca\": \"-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----\"," +
                  "    \"certificate\": \"-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----\"," +
                  "    \"private_key\": \"-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----\"" +
                  "  }" +
                  "}");

          response = mockMvc.perform(put);
        });

        it("returns the secret as json", () -> {
          NamedCertificateSecret expected = (NamedCertificateSecret) secretDataService.findMostRecent(secretName);

          assertThat(expected.getPrivateKey(), equalTo("-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----"));

          response.andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.type").value("certificate"))
              .andExpect(jsonPath("$.value.private_key").value("-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----"))
              .andExpect(jsonPath("$.id").value(expected.getUuid().toString()));
        });
      });

      describe("when all values are empty", () -> {
        it("should return an error with the message 'At least one certificate attribute must be set. Please validate your input and retry your request.'", ()
            -> {
          final MockHttpServletRequestBuilder put = put("/api/v1/data")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{" +
                  "  \"type\":\"certificate\"," +
                  "  \"name\":\"" + secretName + "\"," +
                  "  \"value\": {" +
                  "    \"certificate\": \"\"" +
                  "  }" +
                  "}");
          final String errorMessage = "At least one certificate attribute must be set. Please validate your input and retry your request.";
          mockMvc.perform(put)
              .andExpect(status().isBadRequest())
              .andExpect(jsonPath("$.error").value(errorMessage));
        });
      });

      describe("when the value is an empty hash", () -> {
        it("should return an error message", () -> {
          final MockHttpServletRequestBuilder put = put("/api/v1/data")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{" +
                  "  \"type\":\"certificate\"," +
                  "  \"name\":\"" + secretName + "\"," +
                  "  \"value\": {}" +
                  "}");
          final String errorMessage = "At least one certificate attribute must be set. Please validate your input and retry your request.";
          mockMvc.perform(put)
              .andExpect(status().isBadRequest())
              .andExpect(jsonPath("$.error").value(errorMessage));
        });
      });

      describe("when the value contains unknown keys", () -> {
        it("should return an error", () -> {
          final MockHttpServletRequestBuilder put = put("/api/v1/data")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{" +
                  "  \"type\":\"certificate\"," +
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
    });
  }

}
