package io.pivotal.security.controller.v1.permissions;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.data.AccessControlDataService;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.helper.JsonHelper;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessControlOperation;
import io.pivotal.security.request.AccessEntryRequest;
import io.pivotal.security.view.AccessControlListResponse;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.context.MessageSource;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonHelper.serialize;
import static io.pivotal.security.helper.JsonHelper.serializeToString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
public class AccessEntryControllerTest {
  private AccessControlDataService accessControlDataService;
  private MessageSource messageSource;
  private AccessEntryController subject;
  private MockMvc mockMvc;
  private String errorKey = "$.error";

  {
    beforeEach(() -> {
      accessControlDataService = mock(AccessControlDataService.class);
      messageSource = mock(MessageSource.class);
      subject = new AccessEntryController(
          accessControlDataService,
          messageSource
      );

      MappingJackson2HttpMessageConverter mappingJackson2HttpMessageConverter = new MappingJackson2HttpMessageConverter();
      ObjectMapper objectMapper = JsonHelper.createObjectMapper();
      mappingJackson2HttpMessageConverter.setObjectMapper(objectMapper);
      mockMvc = MockMvcBuilders.standaloneSetup(subject)
          .setMessageConverters(mappingJackson2HttpMessageConverter)
          .build();
    });

    describe("/aces", () -> {
      describe("#POST", () -> {
        describe("when the request has invalid JSON", () -> {
          it("should return an error", () -> {
            when(messageSource.getMessage(eq("error.acl.missing_aces"), eq(null), any(Locale.class)))
                .thenReturn("test-error-message");

            AccessEntryRequest accessEntryRequest = new AccessEntryRequest(
                "test-credential-name",
                null
            );
            byte[] body = serialize(accessEntryRequest);
            MockHttpServletRequestBuilder request = post("/api/v1/aces")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body);

            mockMvc.perform(request)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath(errorKey).value("test-error-message"));
          });
        });

        describe("when the request has valid JSON", () -> {
          it("should return a response containing the new ACE", () -> {
            final ArrayList<AccessControlOperation> operations = newArrayList(AccessControlOperation.READ, AccessControlOperation.WRITE);
            List<AccessControlEntry> accessControlEntries = newArrayList(new AccessControlEntry("test-actor", operations));
            AccessEntryRequest accessEntryRequest = new AccessEntryRequest(
                "test-credential-name",
                accessControlEntries
            );
            AccessControlListResponse expectedResponse = new AccessControlListResponse("test-actor", accessControlEntries);

            when(accessControlDataService.setAccessControlEntry(any(AccessEntryRequest.class)))
                .thenReturn(expectedResponse);

            MockHttpServletRequestBuilder request = post("/api/v1/aces")
                .contentType(MediaType.APPLICATION_JSON)
                .content(serialize(accessEntryRequest));

            final String jsonContent = serializeToString(expectedResponse);
            mockMvc.perform(request)
                .andExpect(status().isOk())
                .andExpect(content().json(jsonContent));

            ArgumentCaptor<AccessEntryRequest> captor = ArgumentCaptor.forClass(AccessEntryRequest.class);
            verify(accessControlDataService, times(1)).setAccessControlEntry(captor.capture());

            AccessEntryRequest actualRequest = captor.getValue();
            assertThat(actualRequest.getCredentialName(), equalTo("test-credential-name"));
            assertThat(actualRequest.getAccessControlEntries(),
                hasItem(allOf(hasProperty("actor", equalTo("test-actor")),
                    hasProperty("allowedOperations", hasItems(AccessControlOperation.READ, AccessControlOperation.WRITE)))));
          });
        });
      });

      describe("#DELETE", () -> {
        describe("when accessControlDataService.delete succeeds", () -> {
          it("should return 204 status ", () -> {
            mockMvc.perform(delete("/api/v1/aces?credential_name=test-name&actor=test-actor"))
                .andExpect(status().isNoContent())
                .andExpect(content().string(""));

            verify(accessControlDataService, times(1))
                .deleteAccessControlEntry("test-name", "test-actor");
          });
        });
        describe("when accessControlDataService.delete throws a NotFound exception", () -> {
          beforeEach(() -> {
            doThrow(new EntryNotFoundException("error.acl.not_found"))
                .when(accessControlDataService)
                .deleteAccessControlEntry("fake-credential", "some-actor");

            when(messageSource.getMessage(eq("error.acl.not_found"), eq(null), any(Locale.class)))
                .thenReturn("The request could not be fulfilled because the access control entry could not be found.");
          });

          it("should return with status 404 and an error message", () -> {
            mockMvc.perform(delete("/api/v1/aces?credential_name=fake-credential&actor=some-actor"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath(errorKey).value("The request could not be fulfilled because the access control entry could not be found."));
          });
        });
      });
    });

    describe("/acls", () -> {
      describe("#GET", () -> {
        describe("when there is no credential_name", () -> {
          it("should return an error", () -> {
            when(messageSource.getMessage(eq("error.missing_query_parameter"), eq(new String[]{"credential_name"}), any(Locale.class)))
                .thenReturn("test-error-message");

            mockMvc.perform(get("/api/v1/acls"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath(errorKey).value("test-error-message"));
          });
        });

        describe("when there is no credential with the specified name", () -> {
          it("should return an error", () -> {
            when(messageSource.getMessage(eq("error.resource_not_found"), eq(null), any(Locale.class)))
                .thenReturn("test-error-message");
            when(accessControlDataService.getAccessControlListResponse("test_credential_name"))
                .thenThrow(new EntryNotFoundException("error.resource_not_found"));

            mockMvc.perform(get("/api/v1/acls?credential_name=test_credential_name"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath(errorKey).value("test-error-message"));
          });
        });

        describe("when the credential exists", () -> {
          it("should return the ACL for the credential", () -> {
            AccessControlListResponse accessControlListResponse = new AccessControlListResponse("test_credential_name", newArrayList());
            when(accessControlDataService.getAccessControlListResponse("test_credential_name"))
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
