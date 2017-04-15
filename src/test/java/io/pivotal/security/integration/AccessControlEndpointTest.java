package io.pivotal.security.integration;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.helper.JsonHelper;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.AccessControlListResponse;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.request.AccessControlOperation.DELETE;
import static io.pivotal.security.request.AccessControlOperation.READ;
import static io.pivotal.security.request.AccessControlOperation.READ_ACL;
import static io.pivotal.security.request.AccessControlOperation.WRITE;
import static io.pivotal.security.request.AccessControlOperation.WRITE_ACL;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static java.util.Arrays.asList;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.beans.SamePropertyValuesAs.samePropertyValuesAs;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
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
      mockMvc = MockMvcBuilders
          .webAppContextSetup(webApplicationContext)
          .apply(springSecurity())
          .build();

      MockHttpServletRequestBuilder put = put("/api/v1/data")
          .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
          .accept(APPLICATION_JSON)
          .contentType(APPLICATION_JSON)
          .content("{"
              + "  \"name\": \"/cred1\","
              + "  \"type\": \"password\","
              + "  \"value\": \"testpassword\""
              + "}");

      this.mockMvc.perform(put)
          .andExpect(status().isOk());
    });

    describe("#GET /acls", () -> {
      it("should return an appropriate error if the credential_name parameter is missing", () -> {
        MockHttpServletRequestBuilder getRequest = get(
            "/api/v1/acls")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
        mockMvc.perform(getRequest)
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error", equalTo("The query parameter credential_name is required for this request.")));
      });

      describe("when the credential exists", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder post = post("/api/v1/aces")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{"
                  + "  \"credential_name\": \"/cred1\",\n"
                  + "  \"access_control_entries\": [\n"
                  + "     { \n"
                  + "       \"actor\": \"dan\",\n"
                  + "       \"operations\": [\"read\"]\n"
                  + "     }]"
                  + "}");

          this.mockMvc.perform(post)
              .andExpect(status().isOk());
        });

        describe("when the user has permission to access the credential's ACL", () -> {
          it("returns the full list of access control entries for the credential", () -> {
            MvcResult result = mockMvc.perform(
                get("/api/v1/acls?credential_name=/cred1")
                    .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            )
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(status().isOk())
                .andDo(print())
                .andReturn();
            String content = result.getResponse().getContentAsString();
            AccessControlListResponse acl = JsonHelper
                .deserialize(content, AccessControlListResponse.class);
            assertThat(acl.getCredentialName(), equalTo("/cred1"));
            assertThat(acl.getAccessControlList(), containsInAnyOrder(
                samePropertyValuesAs(
                    new AccessControlEntry("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d",
                        asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
                samePropertyValuesAs(
                    new AccessControlEntry("dan", asList(READ)))
            ));
          });


          it("returns the full list of access control entries for the credential when leading '/' is missing", () -> {
            MvcResult result = mockMvc.perform(
                get("/api/v1/acls?credential_name=cred1")
                    .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            )
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(status().isOk())
                .andDo(print())
                .andReturn();
            String content = result.getResponse().getContentAsString();
            AccessControlListResponse acl = JsonHelper.deserialize(content, AccessControlListResponse.class);
            assertThat(acl.getCredentialName(), equalTo("/cred1"));
            assertThat(acl.getAccessControlList(), containsInAnyOrder(
                samePropertyValuesAs(
                    new AccessControlEntry("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
                samePropertyValuesAs(
                    new AccessControlEntry("dan", asList(READ)))
            ));
          });
        });

        //Currently commenting this test out while a decision is made around how to write integration tests around ACL enforcement.
//        it("rejects users who lack permission to access the credential's ACL", () -> {
//          // Credential was created with UAA_OAUTH2_PASSWORD_GRANT_TOKEN
//          final MockHttpServletRequestBuilder get = get("/api/v1/acls?credential_name=/cred1")
//              .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
//              .accept(APPLICATION_JSON);
//
//          String expectedError = "The request could not be fulfilled because the resource could not be found.";
//          this.mockMvc.perform(get)
//              .andExpect(status().isNotFound())
//              .andExpect(jsonPath("$.error", equalTo(
//                  expectedError)));
//        });
      });

      describe("when the credential doesn't exist", () -> {
        final String unicorn = "/unicorn";

        it("returns the full list of access control entries for the credential", () -> {
          mockMvc.perform(
              get("/api/v1/acls?credential_name=" + unicorn)
                  .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
          ).andExpect(status().isNotFound())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.error", equalTo(
                  "The request could not be fulfilled "
                      + "because the resource could not be found.")));
        });
      });
    });

    describe("#DELETE /aces", () -> {
      it("should return an appropriate error if the credential_name parameter is missing", () -> {
        MockHttpServletRequestBuilder deleteRequest = delete(
            "/api/v1/aces?actor=dan")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
        mockMvc.perform(deleteRequest)
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error", equalTo("The query parameter credential_name is required for this request.")));
      });

      it("should return an appropriate error if the actor parameter is missing", () -> {
        MockHttpServletRequestBuilder deleteRequest = delete(
            "/api/v1/aces?credential_name=octopus")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
        mockMvc.perform(deleteRequest)
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error", equalTo("The query parameter actor is required for this request.")));
      });

      describe("when deleting an ACE for a specified credential & actor", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder post = post("/api/v1/aces")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{"
                  + "  \"credential_name\": \"/cred1\",\n"
                  + "  \"access_control_entries\": [\n"
                  + "     { \n"
                  + "       \"actor\": \"dan\",\n"
                  + "       \"operations\": [\"read\"]\n"
                  + "     }]"
                  + "}");

          mockMvc.perform(post)
              .andExpect(status().isOk());
        });

        describe("when the specified actor has an ACE with the specified credential", () -> {
          it("should delete the ACE from the resource's ACL", () -> {
            mockMvc.perform(
                get("/api/v1/acls?credential_name=cred1")
                    .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_control_list").isNotEmpty());

            mockMvc.perform(
                delete("/api/v1/aces?credential_name=/cred1&actor=dan")
                    .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            )
                .andExpect(status().isNoContent());

            mockMvc.perform(
                get("/api/v1/acls?credential_name=/cred1")
                    .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_control_list", hasSize(1)));
          });
        });

        describe("when the ACE does not exist", () -> {
          it("should return a 'not found' error response", () -> {
            mockMvc.perform(
                get("/api/v1/acls?credential_name=/not-valid")
                    .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            )
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value(
                    "The request could not be fulfilled because the resource could not be found."));

          });
        });
      });
    });

    describe("#POST /aces", () -> {
      describe("when permissions don't exist", () -> {
        it("returns the full Access Control List for user", () -> {
          final MockHttpServletRequestBuilder post = post("/api/v1/aces")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{"
                  + "  \"credential_name\": \"/cred1\",\n"
                  + "  \"access_control_entries\": [\n"
                  + "     { \n"
                  + "       \"actor\": \"dan\",\n"
                  + "       \"operations\": [\"read\"]\n"
                  + "     }]"
                  + "}");

          final MockHttpServletRequestBuilder get = get("/api/v1/acls?credential_name=/cred1")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON);

          MvcResult result = this.mockMvc.perform(post).andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(status().isOk())
              .andDo(print())
              .andReturn();
          String content = result.getResponse().getContentAsString();
          AccessControlListResponse acl = JsonHelper.deserialize(content, AccessControlListResponse.class);
          assertThat(acl.getAccessControlList(), hasSize(2));
          assertThat(acl.getCredentialName(), equalTo("/cred1"));
          assertThat(acl.getAccessControlList(), containsInAnyOrder(
              samePropertyValuesAs(
                  new AccessControlEntry("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
              samePropertyValuesAs(
                  new AccessControlEntry("dan", asList(READ)))
          ));

          this.mockMvc.perform(get)
              .andExpect(status().isOk());
        });
      });

      describe("when permissions does exist", () -> {
        it("returns the full updated Access Control List for user", () -> {
          final MockHttpServletRequestBuilder initPost = post("/api/v1/aces")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{"
                  + "  \"credential_name\": \"/cred1\",\n"
                  + "  \"access_control_entries\": [\n"
                  + "     { \n"
                  + "       \"actor\": \"dan\",\n"
                  + "       \"operations\": [\"read\"]\n"
                  + "     }]"
                  + "}");

          final MockHttpServletRequestBuilder updatePost = post("/api/v1/aces")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{"
                  + "  \"credential_name\": \"/cred1\",\n"
                  + "  \"access_control_entries\": [\n"
                  + "     { \n"
                  + "       \"actor\": \"dan\",\n"
                  + "       \"operations\": [\"write\"]\n"
                  + "     }]"
                  + "}");

          final MockHttpServletRequestBuilder get = get("/api/v1/acls?credential_name=/cred1")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON);

          this.mockMvc.perform(initPost);

          MvcResult result = this.mockMvc.perform(updatePost).andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(status().isOk())
              .andDo(print())
              .andReturn();
          String content = result.getResponse().getContentAsString();
          AccessControlListResponse acl = JsonHelper.deserialize(content, AccessControlListResponse.class);
          assertThat(acl.getCredentialName(), equalTo("/cred1"));
          assertThat(acl.getAccessControlList(), containsInAnyOrder(
              samePropertyValuesAs(
                  new AccessControlEntry("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
              samePropertyValuesAs(
                  new AccessControlEntry("dan", asList(READ, WRITE)))
          ));

          this.mockMvc.perform(get)
              .andExpect(status().isOk());
        });
      });

      it("prepends missing '/' in credential name and returns the full Access Control List for user", () -> {

        final MockHttpServletRequestBuilder put = put("/api/v1/data")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{"
                + "  \"name\": \"/cred2\","
                + "  \"type\": \"password\","
                + "  \"value\": \"testpassword\""
                + "}");

        this.mockMvc.perform(put)
            .andExpect(status().isOk());

        final MockHttpServletRequestBuilder post = post("/api/v1/aces")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{"
                + "  \"credential_name\": \"cred2\",\n"
                + "  \"access_control_entries\": [\n"
                + "     { \n"
                + "       \"actor\": \"dan\",\n"
                + "       \"operations\": [\"read\"]\n"
                + "     }]"
                + "}");

        final MockHttpServletRequestBuilder get = get("/api/v1/acls?credential_name=/cred2")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON);

        MvcResult result = this.mockMvc.perform(post).andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(status().isOk())
            .andDo(print())
            .andReturn();
        String content = result.getResponse().getContentAsString();
        AccessControlListResponse acl = JsonHelper.deserialize(content, AccessControlListResponse.class);
        assertThat(acl.getCredentialName(), equalTo("/cred2"));
        assertThat(acl.getAccessControlList(), hasSize(2));
        assertThat(acl.getAccessControlList(), containsInAnyOrder(
            samePropertyValuesAs(
                new AccessControlEntry("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
            samePropertyValuesAs(
                new AccessControlEntry("dan", asList(READ)))
        ));

        this.mockMvc.perform(get)
            .andExpect(status().isOk());
      });

      describe("when malformed json is sent", () -> {
        it("returns a nice error message", () -> {
          final String malformedJson = "{"
              + "  \"credential_name\": \"foo\","
              + "  \"access_control_entries\": ["
              + "     {"
              + "       \"actor\": \"dan\","
              + "       \"operations\":"
              + "     }]"
              + "}";
          final MockHttpServletRequestBuilder post = post("/api/v1/aces")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content(malformedJson);

          this.mockMvc.perform(post).andExpect(status().isBadRequest())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.error", equalTo(
                  "The request could not be fulfilled because the request path or body did"
                      + " not meet expectation. Please check the documentation for required "
                      + "formatting and retry your request.")));
        });

        it("returns a nice error message for different kinds of payloads", () -> {
          final String malformedJson = "{"
              + "  \"credential_name\": \"foo\""
              + "  \"access_control_entries\": ["
              + "     {"
              + "       \"actor\": \"dan\","
              + "       \"operations\":[\"read\"]"
              + "     }]"
              + "}";
          final MockHttpServletRequestBuilder post = post("/api/v1/aces")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content(malformedJson);

          this.mockMvc.perform(post).andExpect(status().isBadRequest())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.error", equalTo(
                  "The request could not be fulfilled because the request path or body did"
                      + " not meet expectation. Please check the documentation for required"
                      + " formatting and retry your request.")));
        });
      });

      it("returns a 404 status and message if the credential does not exist", () -> {
        final MockHttpServletRequestBuilder post = post("/api/v1/aces")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{"
                + "  \"credential_name\": \"/this-is-a-fake-credential\",\n"
                + "  \"access_control_entries\": [\n"
                + "     { \n"
                + "       \"actor\": \"dan\",\n"
                + "       \"operations\": [\"read\"]\n"
                + "     }]"
                + "}");

        this.mockMvc.perform(post).andExpect(status().isNotFound())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.error", equalTo(
                "The request could not be fulfilled because the resource could not be found.")));
      });

      describe("when posting access control entry for user and credential with invalid operation", () -> {
        it("returns an error", () -> {
          final MockHttpServletRequestBuilder post = post("/api/v1/aces")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{"
                  + "  \"credential_name\": \"cred1\",\n"
                  + "  \"access_control_entries\": [\n"
                  + "     { \n"
                  + "       \"actor\": \"dan\",\n"
                  + "       \"operations\": [\"unicorn\"]\n"
                  + "     }]"
                  + "}");

          this.mockMvc.perform(post).andExpect(status().isBadRequest())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.error").value(
                  "The provided operation is not supported."
                      + " Valid values include read, write, delete, read_acl, and write_acl."));
        });
      });
    });
  }
}
