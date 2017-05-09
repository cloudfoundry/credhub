package io.pivotal.security.controller.v1.permissions;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.audit.EventAuditLogService;
import io.pivotal.security.audit.RequestUuid;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.handler.AccessControlHandler;
import io.pivotal.security.helper.JsonHelper;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessControlOperation;
import io.pivotal.security.view.AccessControlListResponse;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;
import java.util.function.Function;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
public class AccessControlEntryControllerTest {

  private AccessControlEntryController subject;
  private AccessControlHandler accessControlHandler;
  private EventAuditLogService eventAuditLogService;
  private MockMvc mockMvc;

  {
    beforeEach(() -> {
      accessControlHandler = mock(AccessControlHandler.class);
      eventAuditLogService = mock(EventAuditLogService.class);

      when(eventAuditLogService.auditEvents(any(RequestUuid.class), any(UserContext.class), any(Function.class)))
          .thenAnswer(invocation -> invocation.getArgumentAt(2, Function.class).apply(newArrayList()));

      subject = new AccessControlEntryController(accessControlHandler, eventAuditLogService);

      MappingJackson2HttpMessageConverter mappingJackson2HttpMessageConverter =
          new MappingJackson2HttpMessageConverter();
      ObjectMapper objectMapper = JsonHelper.createObjectMapper();
      mappingJackson2HttpMessageConverter.setObjectMapper(objectMapper);
      mockMvc = MockMvcBuilders.standaloneSetup(subject)
          .setMessageConverters(mappingJackson2HttpMessageConverter)
          .build();
    });

    describe("/api/v1/aces", () -> {
      describe("#POST", () -> {
        it("returns a response containing the new ACE", () -> {
          // language=JSON
          String accessControlEntriesJson = "{\n" +
              "  \"credential_name\": \"test-credential-name\",\n" +
              "  \"access_control_entries\": [\n" +
              "    {\n" +
              "      \"actor\": \"test-actor\",\n" +
              "      \"operations\": [\n" +
              "        \"read\",\n" +
              "        \"write\"\n" +
              "      ]\n" +
              "    }\n" +
              "  ]\n" +
              "}";
          // language=JSON
          String expectedResponse = "{\n" +
              "  \"credential_name\": \"test-actor\",\n" +
              "  \"access_control_list\": [\n" +
              "    {\n" +
              "      \"actor\": \"test-actor\",\n" +
              "      \"operations\": [\n" +
              "        \"read\",\n" +
              "        \"write\"\n" +
              "      ]\n" +
              "    }\n" +
              "  ]\n" +
              "}";

          when(accessControlHandler.setAccessControlEntries(any(String.class), any(List.class)))
              .thenReturn(JsonHelper.deserialize(expectedResponse, AccessControlListResponse.class));

          MockHttpServletRequestBuilder request = post("/api/v1/aces")
              .contentType(MediaType.APPLICATION_JSON)
              .content(accessControlEntriesJson);

          mockMvc.perform(request)
              .andExpect(status().isOk())
              .andExpect(content().json(expectedResponse));

          ArgumentCaptor<List> captor = ArgumentCaptor.forClass(List.class);
          verify(accessControlHandler, times(1)).setAccessControlEntries(eq("test-credential-name"), captor.capture());

          List<AccessControlEntry> accessControlEntries = captor.getValue();
          assertThat(accessControlEntries,
              hasItem(allOf(hasProperty("actor", equalTo("test-actor")),
                  hasProperty("allowedOperations",
                      hasItems(AccessControlOperation.READ, AccessControlOperation.WRITE)))));
        });

        it("validates request JSON on POST", () -> {
          // language=JSON
          String accessControlEntriesJson = "{\n" +
              // no credential_name
              "  \"access_control_entries\": [\n" +
              "    {\n" +
              "      \"actor\": \"test-actor\",\n" +
              "      \"operations\": [\n" +
              "        \"read\",\n" +
              "        \"write\"\n" +
              "      ]\n" +
              "    }\n" +
              "  ]\n" +
              "}";

          MockHttpServletRequestBuilder request = post("/api/v1/aces")
              .contentType(MediaType.APPLICATION_JSON)
              .content(accessControlEntriesJson);

          mockMvc.perform(request)
              .andExpect(status().isBadRequest());
        });
      });

      describe("#DELETE", () -> {
        it("removes ACE, returns 204", () -> {
          mockMvc.perform(delete("/api/v1/aces?credential_name=test-name&actor=test-actor"))
              .andExpect(status().isNoContent())
              .andExpect(content().string(""));

          verify(accessControlHandler, times(1))
              .deleteAccessControlEntries( "test-actor", "test-name");
        });
      });
    });
  }
}
