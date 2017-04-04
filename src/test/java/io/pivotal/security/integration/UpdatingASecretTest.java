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

import javax.servlet.Filter;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
@ActiveProfiles(profiles = {"unit-test",
    "UseRealAuditLogService"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = {CredentialManagerApp.class})
public class UpdatingASecretTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @Autowired
  Filter springSecurityFilterChain;

  private MockMvc mockMvc;
  private String passwordName;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      passwordName = "test-password";

      mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
          .apply(springSecurity())
          .build();
    });

    describe("#post", () -> {
      it("should allow the secret to be updated", () -> {
        String requestBody = "{"
            + "\"type\":\"password\","
            + "\"name\":\""
            + passwordName + "\",\"value\":\"ORIGINAL-VALUE\","
            + "\"overwrite\":true"
            + "}";
        mockMvc.perform(put("/api/v1/data")
            .header("Authorization", "Bearer "
                + UAA_OAUTH2_PASSWORD_GRANT_TOKEN).accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(requestBody)
        )
            .andExpect(status().is2xxSuccessful())
            .andExpect(jsonPath("$.value").value("ORIGINAL-VALUE"));

        requestBody = "{"
            + "\"type\":\"password\","
            + "\"name\":\""
            + passwordName + "\",\"value\":\"NEW-VALUE\","
            + "\"overwrite\":true"
            + "}";

        mockMvc.perform(put("/api/v1/data")
            .header("Authorization", "Bearer "
                + UAA_OAUTH2_PASSWORD_GRANT_TOKEN).accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(requestBody)
        )
            .andExpect(status().is2xxSuccessful())
            .andExpect(jsonPath("$.value").value("NEW-VALUE"));
      });
    });
  }
}
