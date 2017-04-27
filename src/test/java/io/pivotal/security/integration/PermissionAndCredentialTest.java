package io.pivotal.security.integration;

import com.greghaskins.spectrum.Spectrum;
import com.greghaskins.spectrum.Spectrum.Block;
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

import java.util.function.Supplier;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.request.AccessControlOperation.DELETE;
import static io.pivotal.security.request.AccessControlOperation.READ;
import static io.pivotal.security.request.AccessControlOperation.READ_ACL;
import static io.pivotal.security.request.AccessControlOperation.WRITE;
import static io.pivotal.security.request.AccessControlOperation.WRITE_ACL;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static io.pivotal.security.util.CertificateStringConstants.SELF_SIGNED_CERT_WITH_CLIENT_AUTH_EXT;
import static io.pivotal.security.util.X509TestUtil.cert;
import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.beans.SamePropertyValuesAs.samePropertyValuesAs;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.x509;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
@ActiveProfiles(profiles = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = {CredentialManagerApp.class})
public class PermissionAndCredentialTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
          .apply(springSecurity())
          .build();
    });

    describe("#put", testPermissionAndCredentialBehavior("  ,\"value\":\"ORIGINAL-VALUE\"", () -> put("/api/v1/data")));
    describe("#post", testPermissionAndCredentialBehavior("", () -> post("/api/v1/data")));
  }

  private Block testPermissionAndCredentialBehavior(
      String additionalJsonPayload,
      Supplier<MockHttpServletRequestBuilder> requestBuilderProvider) {
    return () -> {
      describe("with a credential and no ace", () -> {
        describe("and UAA authentication", () -> {
          describe("and a password grant", () -> {
            it("should set the credential giving current user read and write permission", () -> {
              String requestBody = "{\n"
                  + "  \"type\":\"password\",\n"
                  + "  \"name\":\"/test-password\"\n"
                  + additionalJsonPayload
                  + "}";

              mockMvc.perform(requestBuilderProvider.get()
                  .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                  .accept(APPLICATION_JSON)
                  .contentType(APPLICATION_JSON)
                  .content(requestBody))

                  .andExpect(status().isOk())
                  .andExpect(jsonPath("$.type", equalTo("password")));

              MvcResult result = mockMvc
                  .perform(get("/api/v1/acls?credential_name=" + "/test-password")
                      .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN))
                  .andDo(print())
                  .andExpect(status().isOk())
                  .andReturn();
              String content = result.getResponse().getContentAsString();
              AccessControlListResponse acl = JsonHelper
                  .deserialize(content, AccessControlListResponse.class);
              assertThat(acl.getCredentialName(), equalTo("/test-password"));
              assertThat(acl.getAccessControlList(), containsInAnyOrder(
                  samePropertyValuesAs(
                      new AccessControlEntry("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d",
                          asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL)))));
            });
          });

          describe("and a client credential", () -> {
            it("should set the credential giving current user read and write permission", () -> {
              String requestBody = "{\n"
                  + "  \"type\":\"password\",\n"
                  + "  \"name\":\"/test-password\"\n"
                  + additionalJsonPayload
                  + "}";

              mockMvc.perform(requestBuilderProvider.get()
                  .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
                  .accept(APPLICATION_JSON)
                  .contentType(APPLICATION_JSON)
                  .content(requestBody))

                  .andExpect(status().isOk())
                  .andExpect(jsonPath("$.type", equalTo("password")));

              MvcResult result = mockMvc
                  .perform(get("/api/v1/acls?credential_name=" + "/test-password")
                      .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN))
                  .andDo(print())
                  .andExpect(status().isOk())
                  .andReturn();
              String content = result.getResponse().getContentAsString();
              AccessControlListResponse acl = JsonHelper
                  .deserialize(content, AccessControlListResponse.class);
              assertThat(acl.getCredentialName(), equalTo("/test-password"));
              assertThat(acl.getAccessControlList(), containsInAnyOrder(
                  samePropertyValuesAs(
                      new AccessControlEntry("uaa-client:credhub_test",
                          asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL)))));
            });
          });
        });

        describe("and mTLS authentication", () -> {
          it("should set the credential giving current user read and write permission", () -> {
            // language=JSON
            String requestBody = "{\n"
                + "  \"type\":\"password\",\n"
                + "  \"name\":\"/test-password\"\n"
                + additionalJsonPayload
                + "}";

            mockMvc.perform(requestBuilderProvider.get()
                .with(x509(cert(SELF_SIGNED_CERT_WITH_CLIENT_AUTH_EXT)))
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(requestBody))

                .andExpect(status().isOk())
                .andExpect(jsonPath("$.type", equalTo("password")));

            MvcResult result = mockMvc
                .perform(get("/api/v1/acls?credential_name=" + "/test-password")
                    .with(x509(cert(SELF_SIGNED_CERT_WITH_CLIENT_AUTH_EXT))))
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn();
            String content = result.getResponse().getContentAsString();
            AccessControlListResponse acl = JsonHelper
                .deserialize(content, AccessControlListResponse.class);
            assertThat(acl.getCredentialName(), equalTo("/test-password"));
            assertThat(acl.getAccessControlList(), containsInAnyOrder(
                samePropertyValuesAs(
                    new AccessControlEntry("mtls-app:a12345e5-b2b0-4648-a0d0-772d3d399dcb",
                        asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL)))));
          });
        });
      });

      describe("with a new credential and an ace", () -> {
        it("should allow the credential and ACEs to be created", () -> {
          // language=JSON
          String requestBody = "{\n"
              + "  \"type\":\"password\",\n"
              + "  \"name\":\"/test-password\",\n"
              + "  \"overwrite\":true, \n"
              + "  \"access_control_entries\": [{\n"
              + "    \"actor\": \"mtls-app:app1-guid\",\n"
              + "    \"operations\": [\"read\"]\n"
              + "  }]\n"
              + additionalJsonPayload
              + "}";

          mockMvc.perform(requestBuilderProvider.get()
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content(requestBody))

              .andExpect(status().isOk())
              .andExpect(jsonPath("$.type", equalTo("password")));

          MvcResult result = mockMvc.perform(get("/api/v1/acls?credential_name=" + "/test-password")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN))
              .andExpect(status().isOk())
              .andDo(print())
              .andReturn();
          String content = result.getResponse().getContentAsString();
          AccessControlListResponse acl = JsonHelper
              .deserialize(content, AccessControlListResponse.class);
          assertThat(acl.getCredentialName(), equalTo("/test-password"));
          assertThat(acl.getAccessControlList(), containsInAnyOrder(
              samePropertyValuesAs(
                  new AccessControlEntry("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d",
                      asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
              samePropertyValuesAs(
                  new AccessControlEntry("mtls-app:app1-guid", asList(READ)))
          ));
        });
      });

      describe("with an existing credential and an ace", () -> {
        beforeEach(() -> {
          // language=JSON
          String requestBody = "{\n"
              + "  \"type\":\"password\",\n"
              + "  \"name\":\"/test-password\",\n"
              + "  \"overwrite\":true, \n"
              + "  \"access_control_entries\": [{\n"
              + "    \"actor\": \"uaa-client:credhub_test\",\n"
              + "    \"operations\": [\"read\", \"write\"]\n"
              + "  }]"
              + additionalJsonPayload
              + "}";

          mockMvc.perform(requestBuilderProvider.get()
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content(requestBody))

              .andExpect(status().isOk())
              .andExpect(jsonPath("$.type", equalTo("password")));
        });

        describe("and overwrite set to true", () -> {
          it("should append new ACEs and not add full permissions for the current user", () -> {
            // language=JSON
            String requestBodyWithNewAces = "{\n"
                + "  \"type\":\"password\",\n"
                + "  \"name\":\"/test-password\",\n"
                + "  \"overwrite\":true, \n"
                + "  \"access_control_entries\": [{\n"
                + "    \"actor\": \"mtls-app:app1-guid\",\n"
                + "    \"operations\": [\"write\"]},\n"
                + "    {\"actor\": \"uaa-client:credhub_test\",\n"
                + "    \"operations\": [\"read\", \"write\", \"delete\"]\n"
                + "  }]\n"
                + additionalJsonPayload
                + "}";

            mockMvc.perform(requestBuilderProvider.get()
                .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(requestBodyWithNewAces))

                .andExpect(status().isOk())
                .andExpect(jsonPath("$.type", equalTo("password")));

            MvcResult result = mockMvc
                .perform(get("/api/v1/acls?credential_name=" + "/test-password")
                    .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN))
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn();
            String content = result.getResponse().getContentAsString();
            AccessControlListResponse acl = JsonHelper
                .deserialize(content, AccessControlListResponse.class);
            assertThat(acl.getCredentialName(), equalTo("/test-password"));
            assertThat(acl.getAccessControlList(), containsInAnyOrder(
                samePropertyValuesAs(
                    new AccessControlEntry("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d",
                        asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
                samePropertyValuesAs(
                    new AccessControlEntry("mtls-app:app1-guid",
                        asList(WRITE))),
                samePropertyValuesAs(
                    new AccessControlEntry("uaa-client:credhub_test",
                        asList(READ, WRITE, DELETE)))));
          });
        });

        describe("and overwrite set to false", () -> {
          it("should not append new ACEs and not add full permissions for the current user", () -> {
            // language=JSON
            String requestBodyWithNewAces = "{\n"
                + "  \"type\":\"password\",\n"
                + "  \"name\":\"/test-password\",\n"
                + "  \"overwrite\":false, \n"
                + "  \"access_control_entries\": [{\n"
                + "    \"actor\": \"mtls-app:app1-guid\",\n"
                + "    \"operations\": [\"write\"]},\n"
                + "    {\"actor\": \"uaa-client:credhub_test\",\n"
                + "    \"operations\": [\"read\", \"write\", \"delete\"]\n"
                + "  }]\n"
                + additionalJsonPayload
                + "}";

            mockMvc.perform(requestBuilderProvider.get()
                .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(requestBodyWithNewAces))

                .andExpect(status().isOk())
                .andExpect(jsonPath("$.type", equalTo("password")));

            MvcResult result = mockMvc
                .perform(get("/api/v1/acls?credential_name=" + "/test-password")
                    .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN))
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn();
            String content = result.getResponse().getContentAsString();
            AccessControlListResponse acl = JsonHelper
                .deserialize(content, AccessControlListResponse.class);
            assertThat(acl.getCredentialName(), equalTo("/test-password"));
            assertThat(acl.getAccessControlList(), containsInAnyOrder(
                samePropertyValuesAs(
                    new AccessControlEntry("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d",
                        asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
                samePropertyValuesAs(
                    new AccessControlEntry("uaa-client:credhub_test",
                        asList(READ, WRITE)))));
          });
        });
      });

      describe("when posting access control entry for user and credential with invalid operation", () -> {
        it("returns an error", () -> {
          final MockHttpServletRequestBuilder put = requestBuilderProvider.get()
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{\n"
                  + "  \"type\":\"password\",\n"
                  + "  \"name\":\"/test-password\",\n"
                  + "  \"overwrite\":true, \n"
                  + "  \"access_control_entries\": [{\n"
                  + "    \"actor\": \"mtls-app:app1-guid\",\n"
                  + "    \"operations\": [\"unicorn\"]\n"
                  + "  }]\n"
                  + additionalJsonPayload
                  + "}");

          this.mockMvc.perform(put).andExpect(status().is4xxClientError())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.error").value(
                  "The provided operation is not supported."
                      + " Valid values include read, write, delete, read_acl, and write_acl."));
        });
      });
    };
  }
}
