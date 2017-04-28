package io.pivotal.security.controller.v1.credential;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.ValueCredential;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.exceptions.KeyNotFoundException;
import io.pivotal.security.exceptions.PermissionException;
import io.pivotal.security.helper.AuditingHelper;
import io.pivotal.security.repository.EventAuditRecordRepository;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;
import java.util.function.Consumer;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class CredentialsControllerGetTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @SpyBean
  Encryptor encryptor;

  @SpyBean
  PermissionService permissionService;

  @Autowired
  RequestAuditRecordRepository requestAuditRecordRepository;

  @Autowired
  EventAuditRecordRepository eventAuditRecordRepository;

  @SpyBean
  CredentialDataService credentialDataService;

  @MockBean
  CurrentTimeProvider mockCurrentTimeProvider;

  private AuditingHelper auditingHelper;

  private MockMvc mockMvc;

  private Instant frozenTime = Instant.ofEpochSecond(1400011001L);

  private Consumer<Long> fakeTimeSetter;

  private final String credentialName = "/my-namespace/controllerGetTest/credential-name";
  private ResultActions response;

  private UUID uuid;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      fakeTimeSetter = mockOutCurrentTimeProvider(mockCurrentTimeProvider);

      fakeTimeSetter.accept(frozenTime.toEpochMilli());

      ReflectionTestUtils
          .setField(permissionService, PermissionService.class, "enforcePermissions", false,
              boolean.class);

      mockMvc = MockMvcBuilders
          .webAppContextSetup(webApplicationContext)
          .apply(springSecurity())
          .build();

      auditingHelper = new AuditingHelper(requestAuditRecordRepository, eventAuditRecordRepository);
    });

    describe("getting a credential", () -> {
      final String credentialValue = "my value";

      beforeEach(() -> {
        uuid = UUID.randomUUID();
        ValueCredential valueCredential1 = new ValueCredential(credentialName)
            .setEncryptor(encryptor)
            .setUuid(uuid)
            .setVersionCreatedAt(frozenTime);
        ValueCredential valueCredential2 = new ValueCredential(credentialName)
            .setEncryptor(encryptor)
            .setUuid(uuid)
            .setVersionCreatedAt(frozenTime);

        doReturn(credentialValue).when(encryptor)
            .decrypt(any());

        doReturn(
            valueCredential1
        ).when(credentialDataService).findMostRecent(credentialName);
        doReturn(
            newArrayList(valueCredential1, valueCredential2)
        ).when(credentialDataService).findAllByName(credentialName.toUpperCase());
        doReturn(
            valueCredential1
        ).when(credentialDataService).findMostRecent(credentialName.toUpperCase());
        doReturn(
            valueCredential1
        ).when(credentialDataService).findByUuid(uuid.toString());
      });

      describe(
          "case insensitive get credential by name (with name query param, and no leading slash)",
          makeGetByNameBlock(
              credentialValue,
              "/api/v1/data?name=" + credentialName.toUpperCase(),
              "/api/v1/data?name=invalid_name", "$.data[0]"
          ));

      describe(
          "when user does not have permissions to retrieve the credential",
          makeGetByNameBlockWithNoPermissions(
              credentialValue,
              "/api/v1/data?name=" + credentialName.toUpperCase(),
              "/api/v1/data?name=invalid_name", "$.data[0]"
          ));

      describe("getting a credential by name when name has multiple leading slashes", () -> {
        it("returns NOT_FOUND", () -> {
          final MockHttpServletRequestBuilder get = get(
              "/api/v1/data?name=//" + credentialName.toUpperCase())
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON);

          mockMvc.perform(get)
              .andExpect(status().isNotFound())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(
                  jsonPath("$.error")
                      .value("Credential not found. Please validate your input " +
                          "and retry your request.")
              );
        });
      });

      describe("when passing a 'current' query parameter", () -> {
        it("when true should return only the most recent version", () -> {
          mockMvc.perform(get("/api/v1/data?current=true&name=" + credentialName.toUpperCase())
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON))
              .andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.data", hasSize(1)));

          verify(credentialDataService).findMostRecent(credentialName.toUpperCase());
        });

        it("when false should return all versions", () -> {
          mockMvc.perform(get("/api/v1/data?current=false&name=" + credentialName.toUpperCase())
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON))
              .andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.data", hasSize(greaterThan(1))));
        });

        it("when omitted should return all versions", () -> {
          mockMvc.perform(get("/api/v1/data?name=" + credentialName.toUpperCase())
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON))
              .andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.data", hasSize(greaterThan(1))));
        });

        it("returns an error when name is not given", () -> {
          final MockHttpServletRequestBuilder get = get("/api/v1/data?name=")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON);

          mockMvc.perform(get)
              .andExpect(status().is4xxClientError())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(
                  jsonPath("$.error")
                      .value("The query parameter name is required for this request.")
              );
        });
      });

      describe("getting a credential by id", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder get = get("/api/v1/data/" + uuid)
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON);

          this.response = mockMvc.perform(get);
        });

        it("should return the credential", () -> {
          this.response.andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.type").value("value"))
              .andExpect(jsonPath("$.value").value(credentialValue))
              .andExpect(jsonPath("$.id").value(uuid.toString()))
              .andExpect(jsonPath("$.version_created_at").value(frozenTime.toString()));
        });

        it("persists an audit entry", () -> {
          auditingHelper.verifyAuditing(
              CREDENTIAL_ACCESS,
              credentialName,
              "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d",
              "/api/v1/data/" + uuid.toString(),
              200);
        });
      });
    });

    describe("when key not present", () -> {
      beforeEach(() -> {
        uuid = UUID.randomUUID();
        ValueCredential valueCredential =
            new ValueCredential(credentialName)
                .setEncryptor(encryptor)
                .setUuid(uuid)
                .setVersionCreatedAt(frozenTime);

        doThrow(new KeyNotFoundException("error.missing_encryption_key"))
            .when(encryptor).decrypt(any());
        doReturn(Arrays.asList(valueCredential)).when(credentialDataService)
            .findAllByName(credentialName.toUpperCase());
      });

      it("returns KEY_NOT_PRESENT", () -> {
        final MockHttpServletRequestBuilder get =
            get("/api/v1/data?name=" + credentialName.toUpperCase())
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .accept(APPLICATION_JSON);

        mockMvc.perform(get)
            .andExpect(status().isInternalServerError())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.error")
                .value("The credential could not be accessed with the provided" +
                    " encryption keys. You must update your deployment configuration " +
                    "to continue."));
      });
    });
  }

  private Spectrum.Block makeGetByNameBlock(
      String credentialValue,
      String validUrl,
      String invalidUrl,
      String jsonPathPrefix
  ) {
    return () -> {
      beforeEach(() -> {
        final MockHttpServletRequestBuilder get = get(validUrl)
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            .accept(APPLICATION_JSON);

        this.response = mockMvc.perform(get);
      });

      it("should return the credential", () -> {
        this.response.andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath(jsonPathPrefix + ".type").value("value"))
            .andExpect(jsonPath(jsonPathPrefix + ".value").value(credentialValue))
            .andExpect(jsonPath(jsonPathPrefix + ".id").value(uuid.toString()))
            .andExpect(
                jsonPath(jsonPathPrefix + ".version_created_at").value(frozenTime.toString()));
      });

      it("persists an audit entry", () -> {
        auditingHelper.verifyAuditing(CREDENTIAL_ACCESS, credentialName, "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", "/api/v1/data", 200);
      });

      it("returns NOT_FOUND when the credential does not exist", () -> {
        final MockHttpServletRequestBuilder get = get(invalidUrl)
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            .accept(APPLICATION_JSON);

        mockMvc.perform(get)
            .andExpect(status().isNotFound())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(
                jsonPath("$.error")
                    .value("Credential not found. Please validate your input and " +
                        "retry your request.")
            );
      });
    };
  }

  private Spectrum.Block makeGetByNameBlockWithNoPermissions(
      String credentialValue,
      String validUrl,
      String invalidUrl,
      String jsonPathPrefix
  ) {
    return () -> {
      beforeEach(() -> {
        ReflectionTestUtils
            .setField(permissionService, PermissionService.class, "enforcePermissions", true,
                boolean.class);

        doThrow(PermissionException.class).when(permissionService)
            .verifyReadPermission(any(UserContext.class), any(CredentialName.class));
        final MockHttpServletRequestBuilder get = get(validUrl)
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            .accept(APPLICATION_JSON);

        this.response = mockMvc.perform(get);
      });

      it("should return credential not found even if request is valid", () -> {
        this.response
            .andExpect(status().isNotFound())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(
                jsonPath("$.error")
                    .value("Credential not found. Please validate your input and " +
                        "retry your request.")
            );
      });

      it("persists an audit entry", () -> {
        auditingHelper.verifyAuditing
            (CREDENTIAL_ACCESS,
                credentialName, "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", "/api/v1/data", 404);
      });

      it("returns NOT_FOUND when the credential does not exist", () -> {
        final MockHttpServletRequestBuilder get = get(invalidUrl)
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            .accept(APPLICATION_JSON);

        mockMvc.perform(get)
            .andExpect(status().isNotFound())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(
                jsonPath("$.error")
                    .value("Credential not found. Please validate your input and " +
                        "retry your request.")
            );
      });
    };
  }
}
