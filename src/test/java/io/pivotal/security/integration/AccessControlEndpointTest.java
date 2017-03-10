package io.pivotal.security.integration;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
public class AccessControlEndpointTest {

  @Autowired
  private WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();

      MockHttpServletRequestBuilder put = put("/api/v1/data")
          .accept(APPLICATION_JSON)
          .contentType(APPLICATION_JSON)
          .content("{" +
              "  \"name\": \"/cred1\"," +
              "  \"type\": \"password\"," +
              "  \"value\": \"testpassword\"" +
              "}");

      this.mockMvc.perform(put)
          .andExpect(status().isOk());
    });

    describe("When posting access control entry for user and credential", () -> {
      it("returns the full Access Control List for user", () -> {
        final MockHttpServletRequestBuilder post = post("/api/v1/aces")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"credential_name\": \"/cred1\",\n" +
                "  \"access_control_entries\": [\n" +
                "     { \n" +
                "       \"actor\": \"dan\",\n" +
                "       \"operations\": [\"read\"]\n" +
                "     }]" +
                "}");

        final MockHttpServletRequestBuilder get = get("/api/v1/acls?credential_name=/cred1")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON);

        this.mockMvc.perform(post).andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.credential_name", equalTo("/cred1")))
            .andExpect(jsonPath("$.access_control_list", hasSize(1)))
            .andExpect(jsonPath("$.access_control_list[0].actor", equalTo("dan")))
            .andExpect(jsonPath("$.access_control_list[0].operations[0]", equalTo("read")));

        this.mockMvc.perform(get)
            .andExpect(status().isOk());
      });

      it("prepends missing '/' in credential name and returns the full Access Control List for user", () -> {

        final MockHttpServletRequestBuilder put = put("/api/v1/data")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"name\": \"/cred2\"," +
                "  \"type\": \"password\"," +
                "  \"value\": \"testpassword\"" +
                "}");

        this.mockMvc.perform(put)
            .andExpect(status().isOk());

        final MockHttpServletRequestBuilder post = post("/api/v1/aces")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"credential_name\": \"cred2\",\n" +
                "  \"access_control_entries\": [\n" +
                "     { \n" +
                "       \"actor\": \"dan\",\n" +
                "       \"operations\": [\"read\"]\n" +
                "     }]" +
                "}");

        final MockHttpServletRequestBuilder get = get("/api/v1/acls?credential_name=/cred2")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON);

        this.mockMvc.perform(post).andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.credential_name", equalTo("/cred2")))
            .andExpect(jsonPath("$.access_control_list", hasSize(1)))
            .andExpect(jsonPath("$.access_control_list[0].actor", equalTo("dan")))
            .andExpect(jsonPath("$.access_control_list[0].operations[0]", equalTo("read")));

        this.mockMvc.perform(get)
            .andExpect(status().isOk());
      });

      describe("when malformed json is sent", () -> {
        it("returns a nice error message", () -> {
          final String malformedJSON = "{" +
              "  \"credential_name\": \"foo\"," +
              "  \"access_control_entries\": [" +
              "     {" +
              "       \"actor\": \"dan\"," +
              "       \"operations\":" +
              "     }]" +
              "}";
          final MockHttpServletRequestBuilder post = post("/api/v1/aces")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content(malformedJSON);

          this.mockMvc.perform(post).andExpect(status().isBadRequest())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.error", equalTo("The request could not be fulfilled because the request path or body did not meet expectation. Please check the documentation for required formatting and retry your request.")));
        });

        it("returns a nice error message for different kinds of payloads", () -> {
          final String malformedJSON = "{" +
              "  \"credential_name\": \"foo\"" +
              "  \"access_control_entries\": [" +
              "     {" +
              "       \"actor\": \"dan\"," +
              "       \"operations\":[\"read\"]" +
              "     }]" +
              "}";
          final MockHttpServletRequestBuilder post = post("/api/v1/aces")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content(malformedJSON);

          this.mockMvc.perform(post).andExpect(status().isBadRequest())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.error", equalTo("The request could not be fulfilled because the request path or body did not meet expectation. Please check the documentation for required formatting and retry your request.")));
        });
      });

      it("returns a 404 status and message if the credential does not exist", () -> {
        final MockHttpServletRequestBuilder post = post("/api/v1/aces")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"credential_name\": \"/this-is-a-fake-credential\",\n" +
                "  \"access_control_entries\": [\n" +
                "     { \n" +
                "       \"actor\": \"dan\",\n" +
                "       \"operations\": [\"read\"]\n" +
                "     }]" +
                "}");

        this.mockMvc.perform(post).andExpect(status().isNotFound())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.error", equalTo("The request could not be fulfilled because the resource could not be found.")));
      });

      describe("When posting access control entry for user and credential with invalid operation", () -> {
        it("returns an error", () -> {
          final MockHttpServletRequestBuilder post = post("/api/v1/aces")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{" +
                  "  \"credential_name\": \"cred1\",\n" +
                  "  \"access_control_entries\": [\n" +
                  "     { \n" +
                  "       \"actor\": \"dan\",\n" +
                  "       \"operations\": [\"unicorn\"]\n" +
                  "     }]" +
                  "}");

          this.mockMvc.perform(post).andExpect(status().is4xxClientError())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.error").value("The provided operation is not supported. Valid values include read and write."));
        });
      });

      describe("When getting access control list by credential name", () -> {
        describe("and the credential exists", () -> {
          beforeEach(() -> {
            final MockHttpServletRequestBuilder post = post("/api/v1/aces")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                    "  \"credential_name\": \"/cred1\",\n" +
                    "  \"access_control_entries\": [\n" +
                    "     { \n" +
                    "       \"actor\": \"dan\",\n" +
                    "       \"operations\": [\"read\"]\n" +
                    "     }]" +
                    "}");

            this.mockMvc.perform(post)
                .andExpect(status().isOk());
          });

          it("returns the full list of access control entries for the credential", () -> {
            mockMvc.perform(get("/api/v1/acls?credential_name=/cred1"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(jsonPath("$.credential_name", equalTo("/cred1")))
                .andExpect(jsonPath("$.access_control_list", hasSize(1)))
                .andExpect(jsonPath("$.access_control_list[0].actor", equalTo("dan")))
                .andExpect(jsonPath("$.access_control_list[0].operations[0]", equalTo("read")));
          });

          it("returns the full list of access control entries for the credential when leading '/' is missing", () -> {
            mockMvc.perform(get("/api/v1/acls?credential_name=cred1"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(jsonPath("$.credential_name", equalTo("/cred1")))
                .andExpect(jsonPath("$.access_control_list", hasSize(1)))
                .andExpect(jsonPath("$.access_control_list[0].actor", equalTo("dan")))
                .andExpect(jsonPath("$.access_control_list[0].operations[0]", equalTo("read")));
          });
        });

        describe("and the credential doesn't exit", () -> {
          final String unicorn = "/unicorn";

          it("returns the full list of access control entries for the credential", () -> {
            mockMvc.perform(get("/api/v1/acls?credential_name=" + unicorn))
                .andExpect(status().isNotFound())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(jsonPath("$.error", equalTo("The request could not be fulfilled because the resource could not be found.")));
          });
        });
      });

      describe("when deleting an ACE for a specified credential & actor", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder post = post("/api/v1/aces")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{" +
                  "  \"credential_name\": \"/cred1\",\n" +
                  "  \"access_control_entries\": [\n" +
                  "     { \n" +
                  "       \"actor\": \"dan\",\n" +
                  "       \"operations\": [\"read\"]\n" +
                  "     }]" +
                  "}");

          mockMvc.perform(post)
              .andExpect(status().isOk());
        });

        describe("when the specified actor has an ACE with the specified credential", () -> {
          it("should delete the ACE from the resource's ACL", () -> {
            mockMvc.perform(get("/api/v1/acls?credential_name=cred1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_control_list").isNotEmpty());

            mockMvc.perform(delete("/api/v1/aces?credential_name=/cred1&actor=dan"))
                .andExpect(status().isNoContent());

            mockMvc.perform(get("/api/v1/acls?credential_name=/cred1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_control_list").isEmpty());
          });
        });

        describe("when the ACE does not exist", () -> {
          it("should return a 'not found' error response", () -> {
            mockMvc.perform(get("/api/v1/acls?credential_name=/not-valid"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("The request could not be fulfilled because the resource could not be found."));

          });
        });
      });
    });
  }
}
