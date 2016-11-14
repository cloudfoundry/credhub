package io.pivotal.security.controller.v1.secret;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.fake.FakePasswordGenerator;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordParameters;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.UUID;
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
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@WebAppConfiguration
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class SecretsControllerRegenerateTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @Autowired
  @InjectMocks
  SecretsController subject;

  @Spy
  @Autowired
  NamedSecretGenerateHandler namedSecretGenerateHandler;

  @Spy
  @Autowired
  NamedSecretSetHandler namedSecretSetHandler;

  @Spy
  @Autowired
  @InjectMocks
  AuditLogService auditLogService;

  @Spy
  @Autowired
  SecretDataService secretDataService;

  @Autowired
  FakePasswordGenerator fakePasswordGenerator;

  private MockMvc mockMvc;

  private Instant frozenTime = Instant.ofEpochSecond(1400011001L);

  private final Consumer<Long> fakeTimeSetter;

  private ResultActions response;

  private UUID uuid;

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

        doReturn(originalSecret).when(secretDataService).findMostRecent("my-password");

        doAnswer(invocation -> {
          NamedPasswordSecret newSecret = invocation.getArgumentAt(0, NamedPasswordSecret.class);
          uuid = UUID.randomUUID();
          newSecret.setUuid(uuid);
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
            .andExpect(jsonPath("$.id").value(uuid.toString()))
            .andExpect(jsonPath("$.updated_at").value(frozenTime.plusSeconds(10).toString()));

        ArgumentCaptor<NamedPasswordSecret> argumentCaptor = ArgumentCaptor.forClass(NamedPasswordSecret.class);
        verify(secretDataService, times(1)).save(argumentCaptor.capture());

        NamedPasswordSecret newPassword = argumentCaptor.getValue();

        assertThat(newPassword.getValue(), equalTo(fakePasswordGenerator.getFakePassword()));
        assertThat(newPassword.getGenerationParameters().isExcludeNumber(), equalTo(true));
      });

      it("persists an audit entry", () -> {
        ArgumentCaptor<Supplier> supplierArgumentCaptor = ArgumentCaptor.forClass(Supplier.class);
        verify(auditLogService, times(1)).performWithAuditing(eq("credential_update"), isA(AuditRecordParameters.class), supplierArgumentCaptor.capture());

        Supplier<ResponseEntity<?>> action = supplierArgumentCaptor.getValue();
        assertThat(action.get().getStatusCode(), equalTo(HttpStatus.OK));
      });
    });

    describe("regenerate request for a non-existent secret", () -> {
      beforeEach(() -> {
        response = mockMvc.perform(post("/api/v1/data/my-password")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{\"regenerate\":true}"));
      });

      it("returns an error", () -> {
        String notFoundJson = "{\"error\": \"Credential not found. Please validate your input and retry your request.\"}";

        response.andExpect(content().json(notFoundJson));
      });

      it("persists an audit entry", () -> {
        ArgumentCaptor<Supplier> supplierArgumentCaptor = ArgumentCaptor.forClass(Supplier.class);
        verify(auditLogService, times(1)).performWithAuditing(eq("credential_update"), isA(AuditRecordParameters.class), supplierArgumentCaptor.capture());

        Supplier<ResponseEntity<?>> action = supplierArgumentCaptor.getValue();
        assertThat(action.get().getStatusCode(), equalTo(HttpStatus.NOT_FOUND));
      });
    });

    describe("when attempting to regenerate a non-regenerated password", () -> {
      beforeEach(() -> {
        NamedPasswordSecret originalSecret = new NamedPasswordSecret("my-password", "abcde");
        doReturn(originalSecret).when(secretDataService).findMostRecent("my-password");

        response = mockMvc.perform(post("/api/v1/data/my-password")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{\"regenerate\":true}"));
      });

      it("returns an error", () -> {
        String cannotRegenerateJson = "{\"error\": \"The credential could not be regenerated because the value was statically set. Only generated credentials may be regenerated.\"}";

        response.andExpect(content().json(cannotRegenerateJson));
      });

      it("persists an audit entry", () -> {
        ArgumentCaptor<Supplier> supplierArgumentCaptor = ArgumentCaptor.forClass(Supplier.class);
        verify(auditLogService, times(1)).performWithAuditing(eq("credential_update"), isA(AuditRecordParameters.class), supplierArgumentCaptor.capture());

        Supplier<ResponseEntity<?>> action = supplierArgumentCaptor.getValue();
        assertThat(action.get().getStatusCode(), equalTo(HttpStatus.BAD_REQUEST));
      });
    });
  }

  private void resetAuditLogMock() throws Exception {
    Mockito.reset(auditLogService);
    doAnswer(invocation -> {
      final Supplier action = invocation.getArgumentAt(2, Supplier.class);
      return action.get();
    }).when(auditLogService).performWithAuditing(isA(String.class), isA(AuditRecordParameters.class), isA(Supplier.class));
  }
}
