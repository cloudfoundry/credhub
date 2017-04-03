package io.pivotal.security.controller.v1.permissions;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.helper.JsonHelper;
import io.pivotal.security.service.permissions.AccessControlViewService;
import io.pivotal.security.view.AccessControlListResponse;
import java.util.Locale;
import org.junit.runner.RunWith;
import org.springframework.context.MessageSource;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@RunWith(Spectrum.class)
public class AccessControlListControllerTest {

  private AccessControlViewService accessControlViewService;
  private MessageSource messageSource;
  private AccessControlListController subject;
  private MockMvc mockMvc;
  private String errorKey = "$.error";

  {
    beforeEach(() -> {
      accessControlViewService = mock(AccessControlViewService.class);
      messageSource = mock(MessageSource.class);
      subject = new AccessControlListController(
          accessControlViewService,
          messageSource
      );

      MappingJackson2HttpMessageConverter mappingJackson2HttpMessageConverter =
          new MappingJackson2HttpMessageConverter();
      ObjectMapper objectMapper = JsonHelper.createObjectMapper();
      mappingJackson2HttpMessageConverter.setObjectMapper(objectMapper);
      mockMvc = MockMvcBuilders.standaloneSetup(subject)
          .setMessageConverters(mappingJackson2HttpMessageConverter)
          .build();
    });

    describe("/acls", () -> {
      describe("#GET", () -> {
        describe("when there is no credential_name", () -> {
          it("should return an error", () -> {
            when(messageSource.getMessage(eq("error.missing_query_parameter"),
                eq(new String[]{"credential_name"}), any(Locale.class)))
                .thenReturn("test-error-message");

            mockMvc.perform(get("/api/v1/acls"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath(errorKey).value("test-error-message"));
          });
        });

        describe("when there is no credential with the specified name", () -> {
          it("should return an error", () -> {
            when(messageSource
                .getMessage(eq("error.resource_not_found"), eq(null), any(Locale.class)))
                .thenReturn("test-error-message");
            when(accessControlViewService.getAccessControlListResponse("test_credential_name"))
                .thenThrow(new EntryNotFoundException("error.resource_not_found"));

            mockMvc.perform(get("/api/v1/acls?credential_name=test_credential_name"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath(errorKey).value("test-error-message"));
          });
        });

        describe("when the credential exists", () -> {
          it("should return the ACL for the credential", () -> {
            AccessControlListResponse accessControlListResponse = new AccessControlListResponse(
                "test_credential_name", newArrayList());
            when(accessControlViewService.getAccessControlListResponse("test_credential_name"))
                .thenReturn(accessControlListResponse);

            mockMvc.perform(get("/api/v1/acls?credential_name=test_credential_name"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credential_name").value("test_credential_name"));
          });
        });
      });
    });
  }
}
