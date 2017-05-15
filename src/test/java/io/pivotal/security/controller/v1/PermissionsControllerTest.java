package io.pivotal.security.controller.v1;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.audit.EventAuditLogService;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.handler.AccessControlHandler;
import io.pivotal.security.helper.JsonHelper;
import io.pivotal.security.view.PermissionsView;
import org.junit.runner.RunWith;
import org.springframework.http.RequestEntity;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.function.Function;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
public class PermissionsControllerTest {

  private PermissionsController subject;
  private AccessControlHandler accessControlHandler;
  private MockMvc mockMvc;
  private EventAuditLogService eventAuditLogService;

  {
    beforeEach(() -> {
      accessControlHandler = mock(AccessControlHandler.class);
      eventAuditLogService = mock(EventAuditLogService.class);

      subject = new PermissionsController(accessControlHandler, eventAuditLogService);

      MappingJackson2HttpMessageConverter mappingJackson2HttpMessageConverter =
        new MappingJackson2HttpMessageConverter();
      ObjectMapper objectMapper = JsonHelper.createObjectMapper();
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

          when(accessControlHandler.getAccessControlListResponse(any(UserContext.class), eq("test_credential_name")))
              .thenReturn(permissionsView);

          when(eventAuditLogService.auditEvent(any(), any(), any())).thenAnswer(answer -> {
            Function<EventAuditRecordParameters, RequestEntity> block = answer.getArgumentAt(2, Function.class);
            return block.apply(mock(EventAuditRecordParameters.class));
          });

          mockMvc.perform(get("/api/v1/permissions?credential_name=test_credential_name"))
              .andExpect(status().isOk())
              .andExpect(jsonPath("$.credential_name").value("test_credential_name"))
              .andExpect(jsonPath("$.permissions").exists()).andDo(print());
        });
      });
    });
  }
}
