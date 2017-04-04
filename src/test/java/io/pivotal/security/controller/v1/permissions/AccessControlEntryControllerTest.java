package io.pivotal.security.controller.v1.permissions;

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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.helper.JsonHelper;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessControlOperation;
import io.pivotal.security.request.AccessEntriesRequest;
import io.pivotal.security.service.permissions.AccessControlViewService;
import io.pivotal.security.view.AccessControlListResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.context.MessageSource;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@RunWith(Spectrum.class)
public class AccessControlEntryControllerTest {

  private AccessControlEntryController subject;
  private AccessControlViewService accessControlViewService;
  private MessageSource messageSource;
  private MockMvc mockMvc;
  private String errorKey = "$.error";

  {
    beforeEach(() -> {
      accessControlViewService = mock(AccessControlViewService.class);
      messageSource = mock(MessageSource.class);
      subject = new AccessControlEntryController(
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

    describe("/aces", () -> {
      describe("#POST", () -> {
        describe("when the request has invalid JSON", () -> {
          it("should return an error", () -> {
            when(
                messageSource.getMessage(eq("error.acl.missing_aces"),
                    eq(null), any(Locale.class)))
                .thenReturn("test-error-message");

            AccessEntriesRequest accessEntriesRequest = new AccessEntriesRequest(
                "test-credential-name",
                null
            );
            byte[] body = serialize(accessEntriesRequest);
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
            final ArrayList<AccessControlOperation> operations = newArrayList(
                AccessControlOperation.READ, AccessControlOperation.WRITE);
            List<AccessControlEntry> accessControlEntries = newArrayList(
                new AccessControlEntry("test-actor", operations));
            AccessEntriesRequest accessEntriesRequest = new AccessEntriesRequest(
                "test-credential-name",
                accessControlEntries
            );
            AccessControlListResponse expectedResponse =
                new AccessControlListResponse("test-actor",
                    accessControlEntries);

            when(accessControlViewService.setAccessControlEntries(any(AccessEntriesRequest.class)))
                .thenReturn(expectedResponse);

            MockHttpServletRequestBuilder request = post("/api/v1/aces")
                .contentType(MediaType.APPLICATION_JSON)
                .content(serialize(accessEntriesRequest));

            final String jsonContent = serializeToString(expectedResponse);
            mockMvc.perform(request)
                .andExpect(status().isOk())
                .andExpect(content().json(jsonContent));

            ArgumentCaptor<AccessEntriesRequest> captor = ArgumentCaptor
                .forClass(AccessEntriesRequest.class);
            verify(accessControlViewService, times(1)).setAccessControlEntries(captor.capture());

            AccessEntriesRequest actualRequest = captor.getValue();
            assertThat(actualRequest.getCredentialName(), equalTo("test-credential-name"));
            assertThat(actualRequest.getAccessControlEntries(),
                hasItem(allOf(hasProperty("actor", equalTo("test-actor")),
                    hasProperty("allowedOperations",
                        hasItems(AccessControlOperation.READ, AccessControlOperation.WRITE)))));
          });
        });
      });

      describe("#DELETE", () -> {
        describe("when accessControlDataService.delete succeeds", () -> {
          it("should return 204 status ", () -> {
            mockMvc.perform(delete("/api/v1/aces?credential_name=test-name&actor=test-actor"))
                .andExpect(status().isNoContent())
                .andExpect(content().string(""));

            verify(accessControlViewService, times(1))
                .deleteAccessControlEntries("test-name", "test-actor");
          });
        });
        describe("when delete throws a NotFound exception", () -> {
          beforeEach(() -> {
            doThrow(new EntryNotFoundException("error.acl.not_found"))
                .when(accessControlViewService)
                .deleteAccessControlEntries("fake-credential", "some-actor");

            when(messageSource.getMessage(eq("error.acl.not_found"), eq(null), any(Locale.class)))
                .thenReturn(
                    "The request could not be fulfilled "
                        + "because the access control entry could not be found.");
          });

          it("should return with status 404 and an error message", () -> {
            mockMvc.perform(delete("/api/v1/aces?credential_name=fake-credential&actor=some-actor"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath(errorKey).value(
                    "The request could not be fulfilled beca"
                        + "use the access control entry could not be found."));
          });
        });
      });
    });
  }
}
