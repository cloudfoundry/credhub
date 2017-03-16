package io.pivotal.security.integration;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_TOKEN;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import javax.servlet.Filter;

@RunWith(Spectrum.class)
@ActiveProfiles(profiles = {"unit-test", "UseRealAuditLogService"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = {CredentialManagerApp.class})
public class SetPermissionAndSecretTest {
  @Autowired
  WebApplicationContext webApplicationContext;

  @Autowired
  Filter springSecurityFilterChain;

  private MockMvc mockMvc;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
          .addFilter(springSecurityFilterChain)
          .build();
    });

    describe("#put", () -> {
      describe("with a new secret", () -> {
        it("should allow the secret and ACEs to be created", () -> {
          // language=JSON
          String requestBody = "{\n" +
              "  \"type\":\"password\",\n" +
              "  \"name\":\"/test-password\",\n" +
              "  \"value\":\"ORIGINAL-VALUE\",\n" +
              "  \"overwrite\":true, \n" +
              "  \"access_control_entries\": [{\n" +
              "    \"actor\": \"app1-guid\",\n" +
              "    \"operations\": [\"read\"]\n" +
              "  }]\n" +
              "}";

          mockMvc.perform(put("/api/v1/data")
              .header("Authorization", "Bearer " + UAA_OAUTH2_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content(requestBody))

              .andExpect(status().isOk())
              .andExpect(jsonPath("$.type", equalTo("password")));

          mockMvc.perform(get("/api/v1/acls?credential_name=" + "/test-password")
              .header("Authorization", "Bearer " + UAA_OAUTH2_TOKEN))
              .andDo(print())
              .andExpect(status().isOk())
              .andExpect(jsonPath("$.credential_name").value("/test-password"))
              .andExpect(jsonPath("$.access_control_list[0].actor").value("app1-guid"))
              .andExpect(jsonPath("$.access_control_list[0].operations[0]").value("read"));
        });
      });

      describe("with an existing secret", () -> {
        beforeEach(() -> {
          // language=JSON
          String requestBody = "{\n" +
              "  \"type\":\"password\",\n" +
              "  \"name\":\"/test-password\",\n" +
              "  \"value\":\"ORIGINAL-VALUE\",\n" +
              "  \"overwrite\":true, \n" +
              "  \"access_control_entries\": [{\n" +
              "    \"actor\": \"app1-guid\",\n" +
              "    \"operations\": [\"read\"]\n" +
              "  }]\n" +
              "}";

          mockMvc.perform(put("/api/v1/data")
              .header("Authorization", "Bearer " + UAA_OAUTH2_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content(requestBody))

              .andExpect(status().isOk())
              .andExpect(jsonPath("$.type", equalTo("password")));
        });

        it("should update ACEs", () -> {
          // language=JSON
          String requestBodyWithNewACEs = "{\n" +
              "  \"type\":\"password\",\n" +
              "  \"name\":\"/test-password\",\n" +
              "  \"value\":\"ORIGINAL-VALUE\",\n" +
              "  \"overwrite\":true, \n" +
              "  \"access_control_entries\": [{\n" +
              "    \"actor\": \"app1-guid\",\n" +
              "    \"operations\": [\"read\", \"write\"]\n" +
              "  }]\n" +
              "}";

          mockMvc.perform(put("/api/v1/data")
              .header("Authorization", "Bearer " + UAA_OAUTH2_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content(requestBodyWithNewACEs))

              .andExpect(status().isOk())
              .andExpect(jsonPath("$.type", equalTo("password")));

          mockMvc.perform(get("/api/v1/acls?credential_name=" + "/test-password")
              .header("Authorization", "Bearer " + UAA_OAUTH2_TOKEN))
              .andDo(print())
              .andExpect(status().isOk())
              .andExpect(jsonPath("$.credential_name").value("/test-password"))
              .andExpect(jsonPath("$.access_control_list[0].actor").value("app1-guid"))
              .andExpect(jsonPath("$.access_control_list[0].operations[0]").value("read"))
              .andExpect(jsonPath("$.access_control_list[0].operations[1]").value("write"));
        });
      });
    });
  }
}
