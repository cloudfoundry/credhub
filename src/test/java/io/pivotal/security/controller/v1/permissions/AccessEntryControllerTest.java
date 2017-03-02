package io.pivotal.security.controller.v1.permissions;

import com.greghaskins.spectrum.Spectrum;

import io.pivotal.security.CredentialManagerApp;
import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessEntryRequest;
import io.pivotal.security.service.AccessControlService;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.AccessEntryResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.core.IsEqual.equalTo;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.Collections;

@RunWith(Spectrum.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
public class AccessEntryControllerTest {

  @Autowired
  private WebApplicationContext webApplicationContext;

  @MockBean
  private AccessControlService accessControlService;

  private MockMvc mockMvc;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
      AccessControlEntry entry = new AccessControlEntry("dan", Collections.singletonList("read"));
      AccessEntryResponse response = new AccessEntryResponse("/cred1", Collections.singletonList(entry));

      when(accessControlService.setAccessControlEntry(any(AccessEntryRequest.class))).thenReturn(response);
      when(accessControlService.getAccessControlEntries("/cred1")).thenReturn(response);

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

        this.mockMvc.perform(post).andExpect(status().isOk())
          .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
          .andExpect(jsonPath("$.credential_name", equalTo("/cred1")))
          .andExpect(jsonPath("$.access_control_list", hasSize(1)))
          .andExpect(jsonPath("$.access_control_list[0].actor", equalTo("dan")))
          .andExpect(jsonPath("$.access_control_list[0].operations[0]", equalTo("read")));

        ArgumentCaptor<AccessEntryRequest> captor = ArgumentCaptor.forClass(AccessEntryRequest.class);
        verify(accessControlService).setAccessControlEntry(captor.capture());

        assertThat(captor.getValue().getCredentialName(), equalTo("/cred1"));
        assertThat(captor.getValue().getAccessControlEntries().get(0).getActor(), equalTo("dan"));
        assertThat(captor.getValue().getAccessControlEntries().get(0).getOperations().get(0), equalTo("read"));
      });
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
      it("returns the full list of access control entries for the credential", () -> {
        mockMvc.perform(get("/api/v1/acls?credential_name=/cred1"))
          .andExpect(status().isOk())
          .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
          .andExpect(jsonPath("$.credential_name", equalTo("/cred1")))
          .andExpect(jsonPath("$.access_control_list", hasSize(1)))
          .andExpect(jsonPath("$.access_control_list[0].actor", equalTo("dan")))
          .andExpect(jsonPath("$.access_control_list[0].operations[0]", equalTo("read")));
      });
    });

  }
}
