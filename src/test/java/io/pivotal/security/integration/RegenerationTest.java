package io.pivotal.security.integration;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import io.pivotal.security.controller.v1.SecretsController;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.fake.FakePasswordGenerator;
import io.pivotal.security.fake.FakeUuidGenerator;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordParameters;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@WebAppConfiguration
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles({"unit-test", "FakeUuidGenerator"})
public class RegenerationTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @Autowired
  @InjectMocks
  SecretsController subject;

  @Mock
  AuditLogService auditLogService;

  @Spy
  SecretDataService secretDataService;

  @Autowired
  FakeUuidGenerator fakeUuidGenerator;

  @Autowired
  FakePasswordGenerator fakePasswordGenerator;

  private MockMvc mockMvc;

  private Instant frozenTime = Instant.ofEpochSecond(1400011001L);

  private final Consumer<Long> fakeTimeSetter;

  private ResultActions response;

  {
    wireAndUnwire(this);
    fakeTimeSetter = mockOutCurrentTimeProvider(this);

    beforeEach(() -> {
      fakeTimeSetter.accept(frozenTime.toEpochMilli());
      mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();

      resetAuditLogMock();
    });

    describe("regenerating a password", () -> {
      beforeEach(() -> {
        NamedPasswordSecret originalSecret = new NamedPasswordSecret("my-password", "original-password");
        PasswordGenerationParameters generationParameters = new PasswordGenerationParameters();

        generationParameters.setExcludeNumber(true);
        originalSecret.setGenerationParameters(generationParameters);

        doReturn(originalSecret).when(secretDataService).findFirstByNameIgnoreCaseOrderByUpdatedAtDesc("my-password");

        doAnswer(invocation -> {
          NamedPasswordSecret newSecret = invocation.getArgumentAt(0, NamedPasswordSecret.class);
          newSecret.setUuid(fakeUuidGenerator.makeUuid());
          newSecret.setUpdatedAt(frozenTime.plusSeconds(10));
          return newSecret;
        }).when(secretDataService).save(any(NamedPasswordSecret.class));

        resetAuditLogMock();

        fakeTimeSetter.accept(frozenTime.plusSeconds(10).toEpochMilli());

        response = mockMvc.perform(post("/api/v1/data/my-password")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{\"regenerate\":true}"));
      });

      it("should regenerate the secret", () -> {
        response.andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.type").value("password"))
            .andExpect(jsonPath("$.id").value(fakeUuidGenerator.getLastUuid()))
            .andExpect(jsonPath("$.updated_at").value(frozenTime.plusSeconds(10).toString()));

        ArgumentCaptor<NamedPasswordSecret> argumentCaptor = ArgumentCaptor.forClass(NamedPasswordSecret.class);
        verify(secretDataService, times(1)).save(argumentCaptor.capture());

        NamedPasswordSecret newPassword = argumentCaptor.getValue();

        assertThat(newPassword.getValue(), equalTo(fakePasswordGenerator.getFakePassword()));
        assertThat(newPassword.getGenerationParameters().isExcludeNumber(), equalTo(true));
      });

      it("persists an audit entry", () -> {
        verify(auditLogService).performWithAuditing(eq("credential_update"), isA(AuditRecordParameters.class), any(Supplier.class));
      });
    });
  }

  private void resetAuditLogMock() throws Exception {
    Mockito.reset(auditLogService);
    when(auditLogService.performWithAuditing(isA(String.class), isA(AuditRecordParameters.class), isA(Supplier.class)))
        .thenAnswer(invocation -> {
          final Supplier action = invocation.getArgumentAt(2, Supplier.class);
          return action.get();
        });
  }
}
