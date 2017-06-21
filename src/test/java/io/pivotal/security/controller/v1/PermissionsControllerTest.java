package io.pivotal.security.controller.v1;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.audit.EventAuditLogService;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.audit.RequestUuid;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.PermissionsDataService;
import io.pivotal.security.handler.PermissionsHandler;
import io.pivotal.security.helper.JsonTestHelper;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.PermissionOperation;
import io.pivotal.security.view.PermissionsView;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
public class PermissionsControllerTest {

  private PermissionsController subject;
  private PermissionsHandler permissionsHandler;
  private MockMvc mockMvc;
  private EventAuditLogService eventAuditLogService;
  private PermissionsDataService permissionsDataService;

  {
    beforeEach(() -> {
      permissionsHandler = mock(PermissionsHandler.class);
      eventAuditLogService = mock(EventAuditLogService.class);
      permissionsDataService = mock(PermissionsDataService.class);

      when(eventAuditLogService.auditEvents(any(RequestUuid.class), any(UserContext.class), any(Function.class)))
          .thenAnswer(invocation -> invocation.getArgumentAt(2, Function.class).apply(newArrayList()));


      subject = new PermissionsController(permissionsHandler, eventAuditLogService,
          permissionsDataService);

      MappingJackson2HttpMessageConverter mappingJackson2HttpMessageConverter =
          new MappingJackson2HttpMessageConverter();
      ObjectMapper objectMapper = JsonTestHelper.createObjectMapper();
      mappingJackson2HttpMessageConverter.setObjectMapper(objectMapper);
      mockMvc = MockMvcBuilders.standaloneSetup(subject)
          .setMessageConverters(mappingJackson2HttpMessageConverter)
          .build();
    });

    describe("/permissions", () -> {
      describe("#GET", () -> {
        it("should return the ACL for the credential", () -> {
          PermissionsView permissionsView = new PermissionsView(
              "test_credential_name", newArrayList());

          when(
              permissionsHandler.getPermissions(any(UserContext.class), eq("test_credential_name")))
              .thenReturn(permissionsView);

          when(eventAuditLogService.auditEvent(any(), any(), any())).thenAnswer(answer -> {
            Function<EventAuditRecordParameters, RequestEntity> block = answer
                .getArgumentAt(2, Function.class);
            return block.apply(mock(EventAuditRecordParameters.class));
          });

          mockMvc.perform(get("/api/v1/permissions?credential_name=test_credential_name"))
              .andExpect(status().isOk())
              .andExpect(jsonPath("$.credential_name").value("test_credential_name"))
              .andExpect(jsonPath("$.permissions").exists()).andDo(print());
        });
      });
    });

    describe("#POST", () -> {
      it("returns a response containing the new ACE", () -> {
        // language=JSON
        String accessControlEntriesJson = "{\n" +
            "  \"credential_name\": \"test-credential-name\",\n" +
            "  \"permissions\": [\n" +
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
            "  \"permissions\": [\n" +
            "    {\n" +
            "      \"actor\": \"test-actor\",\n" +
            "      \"operations\": [\n" +
            "        \"read\",\n" +
            "        \"write\"\n" +
            "      ]\n" +
            "    }\n" +
            "  ]\n" +
            "}";

        when(permissionsHandler
            .setPermissions(any(UserContext.class), any(String.class), any(List.class)))
            .thenReturn(JsonTestHelper.deserialize(expectedResponse, PermissionsView.class));

        MockHttpServletRequestBuilder request = post("/api/v1/permissions")
            .contentType(MediaType.APPLICATION_JSON)
            .content(accessControlEntriesJson);

        mockMvc.perform(request)
            .andExpect(status().isOk())
            .andExpect(content().json(expectedResponse));

        ArgumentCaptor<List> captor = ArgumentCaptor.forClass(List.class);
        verify(permissionsHandler, times(1)).setPermissions(
            any(UserContext.class),
            eq("test-credential-name"),
            captor.capture()
        );

        List<PermissionEntry> accessControlEntries = captor.getValue();
        assertThat(accessControlEntries,
            hasItem(allOf(hasProperty("actor", equalTo("test-actor")),
                hasProperty("allowedOperations",
                    hasItems(PermissionOperation.READ, PermissionOperation.WRITE)))));
      });

      it("validates request JSON on POST", () -> {
        // language=JSON
        String accessControlEntriesJson = "{\n" +
            // no credential_name
            "  \"permissions\": [\n" +
            "    {\n" +
            "      \"actor\": \"test-actor\",\n" +
            "      \"operations\": [\n" +
            "        \"read\",\n" +
            "        \"write\"\n" +
            "      ]\n" +
            "    }\n" +
            "  ]\n" +
            "}";

        MockHttpServletRequestBuilder request = post("/api/v1/permissions")
            .contentType(MediaType.APPLICATION_JSON)
            .content(accessControlEntriesJson);

        mockMvc.perform(request)
            .andExpect(status().isBadRequest());
      });
    });

    describe("#DELETE", () -> {
      it("removes ACE, returns 204", () -> {
        mockMvc.perform(delete("/api/v1/permissions?credential_name=test-name&actor=test-actor"))
            .andExpect(status().isNoContent())
            .andExpect(content().string(""));

        verify(permissionsHandler, times(1))
            .deletePermissionEntry(any(UserContext.class), eq("test-name"), eq("test-actor"));
      });
    });
  }
}
