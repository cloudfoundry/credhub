package io.pivotal.security.controller.v1.secret;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.helper.JsonHelper.serializeToString;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.domain.NamedValueSecret;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessControlOperation;
import io.pivotal.security.request.JsonSetRequest;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Supplier;
import org.apache.commons.lang3.StringUtils;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@RunWith(Spectrum.class)
@ActiveProfiles(profiles = {"unit-test",
    "UseRealAuditLogService"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class SecretsControllerSetTest {

  final String secretValue = "secret-value";
  private final String secretName = "/my-namespace/secretForSetTest/secret-name";
  @Autowired
  WebApplicationContext webApplicationContext;
  @Autowired
  SecretsController subject;
  @SpyBean
  AuditLogService auditLogService;
  @SpyBean
  SecretDataService secretDataService;
  @MockBean
  CurrentTimeProvider mockCurrentTimeProvider;
  private MockMvc mockMvc;
  private Instant frozenTime = Instant.ofEpochSecond(1400011001L);
  private Consumer<Long> fakeTimeSetter;
  private ResultActions response;
  private UUID uuid;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      fakeTimeSetter = mockOutCurrentTimeProvider(mockCurrentTimeProvider);

      fakeTimeSetter.accept(frozenTime.toEpochMilli());
      mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();

      resetAuditLogMock();
    });

    describe("setting a secret", () -> {
      it("should return an error while attempting to create a new secret "
              + "with an unknown/garbage type",
          () -> {
            final MockHttpServletRequestBuilder put = put("/api/v1/data")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{"
                    + "  \"type\":\"foo\","
                    + "  \"name\":\"" + secretName + "\","
                    + "  \"value\":\"" + secretValue + "\""
                    + "}");

            final String errorMessage = "The request does not include a valid type. "
                + "Valid values include 'value', 'json', 'password', 'certificate', "
                + "'ssh' and 'rsa'.";
            mockMvc.perform(put)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(errorMessage));
          });

      describe("via parameter in request body", () -> {
        beforeEach(() -> {

          final MockHttpServletRequestBuilder put = put("/api/v1/data")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{"
                  + "  \"type\":\"value\","
                  + "  \"name\":\"" + secretName + "\","
                  + "  \"value\":\"" + secretValue + "\""
                  + "}");

          response = mockMvc.perform(put);
        });

        it("returns the secret as json", () -> {
          NamedSecret expected = secretDataService.findMostRecent(secretName);

          response.andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.type").value("value"))
              .andExpect(jsonPath("$.value").value(secretValue))
              .andExpect(jsonPath("$.id").value(expected.getUuid().toString()))
              .andExpect(jsonPath("$.version_created_at")
                  .value(expected.getVersionCreatedAt().toString()));
        });

        it("asks the data service to persist the secret", () -> {
          ArgumentCaptor<NamedValueSecret> argumentCaptor = ArgumentCaptor
              .forClass(NamedValueSecret.class);

          verify(secretDataService, times(1)).save(argumentCaptor.capture());

          NamedValueSecret namedValueSecret = argumentCaptor.getValue();
          assertThat(namedValueSecret.getValue(), equalTo(secretValue));
        });

        it("persists an audit entry", () -> {
          ArgumentCaptor<AuditRecordBuilder> auditRecordParamsCaptor = ArgumentCaptor
              .forClass(AuditRecordBuilder.class);
          verify(auditLogService)
              .performWithAuditing(auditRecordParamsCaptor.capture(), any(Supplier.class));

          assertThat(auditRecordParamsCaptor.getValue().getOperationCode(),
              equalTo(CREDENTIAL_UPDATE));
        });

        it("allows secret with '.' in the name", () -> {
          final String testSecretNameWithDot = "test.response";

          mockMvc.perform(put("/api/v1/data")
              .content("{\"type\":\"value\",\"name\":\"" + testSecretNameWithDot + "\",\"value\":\""
                  + "def" + "\"}")
              .contentType(MediaType.APPLICATION_JSON_UTF8))
              .andExpect(status().isOk());
        });
      });

      describe("when name does not have a leading slash", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder put = put("/api/v1/data")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{"
                  + "  \"type\":\"value\","
                  + "  \"name\":\"" + StringUtils.stripStart(secretName, "/") + "\","
                  + "  \"value\":\"" + secretValue + "\""
                  + "}");

          response = mockMvc.perform(put);
        });

        it("returns the secret as json with a slash added to the name", () -> {
          NamedSecret expected = secretDataService.findMostRecent(secretName);

          response.andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.name").value(secretName))
              .andExpect(jsonPath("$.type").value("value"))
              .andExpect(jsonPath("$.value").value(secretValue))
              .andExpect(jsonPath("$.id").value(expected.getUuid().toString()))
              .andExpect(jsonPath("$.version_created_at")
                  .value(expected.getVersionCreatedAt().toString()));
        });
      });

      describe("when a password set request contains access_control_entries", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder put = put("/api/v1/data")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{"
                  + "  \"type\":\"password\","
                  + "  \"name\":\"this-has-an-acl\","
                  + "  \"value\":\"this-ia-a-fake-password\","
                  + "\"access_control_entries\": ["
                  + "{\"actor\": \"app1-guid\","
                  + "\"operations\": [\"read\"]}]"
                  + "}");

          response = mockMvc.perform(put);
        });

        it("sets the ACL for the resource", () -> {
          response.andExpect(status().isOk());
          mockMvc.perform(get("/api/v1/acls?credential_name=this-has-an-acl"))
              .andExpect(status().isOk())
              .andExpect(jsonPath("$.credential_name").value("/this-has-an-acl"))
              .andExpect(jsonPath("$.access_control_list[0].actor", equalTo("app1-guid")))
              .andExpect(jsonPath("$.access_control_list[0].operations[0]", equalTo("read")));

        });
      });

      describe("when a value set request contains access_control_entries", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder put = put("/api/v1/data")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{"
                  + "  \"type\":\"value\","
                  + "  \"name\":\"this-value-has-an-acl\","
                  + "  \"value\":\"some value\","
                  + "\"access_control_entries\": ["
                  + "{\"actor\": \"app2-guid\","
                  + "\"operations\": [\"read\"]}]"
                  + "}");

          response = mockMvc.perform(put);
        });

        it("sets the ACL for the resource", () -> {
          response.andExpect(status().isOk());
          mockMvc.perform(get("/api/v1/acls?credential_name=this-value-has-an-acl"))
              .andExpect(status().isOk())
              .andExpect(jsonPath("$.credential_name").value("/this-value-has-an-acl"))
              .andExpect(jsonPath("$.access_control_list[0].actor", equalTo("app2-guid")))
              .andExpect(jsonPath("$.access_control_list[0].operations[0]", equalTo("read")));

        });
      });

      describe("when a json set request contains access_control_entries", () -> {
        beforeEach(() -> {

          List<AccessControlEntry> accessControlEntries = new ArrayList<>();
          AccessControlEntry entry = new AccessControlEntry();
          entry.setActor("app2-guid");
          entry.setAllowedOperations(Arrays.asList(AccessControlOperation.READ));
          accessControlEntries.add(entry);

          Map<String, Object> nestedValue = new HashMap<>();
          nestedValue.put("num", 10);
          String[] value = {"foo", "bar"};

          Map<String, Object> jsonValue = new HashMap<>();
          jsonValue.put("key", "value");
          jsonValue.put("fancy", nestedValue);
          jsonValue.put("array", value);

          JsonSetRequest request = new JsonSetRequest();
          request.setName("this-json-has-an-acl");
          request.setValue(jsonValue);
          request.setAccessControlEntries(accessControlEntries);
          request.setType("json");

          final MockHttpServletRequestBuilder put = put("/api/v1/data")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content(serializeToString(request));

          response = mockMvc.perform(put);
        });

        it("sets the ACL for the resource", () -> {
          response.andExpect(status().isOk());
          mockMvc.perform(get("/api/v1/acls?credential_name=this-json-has-an-acl"))
              .andExpect(status().isOk())
              .andExpect(jsonPath("$.credential_name").value("/this-json-has-an-acl"))
              .andExpect(jsonPath("$.access_control_list[0].actor", equalTo("app2-guid")))
              .andExpect(jsonPath("$.access_control_list[0].operations[0]", equalTo("read")));

        });
      });

      describe("when a rsa set request contains access_control_entries", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder put = put("/api/v1/data")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{"
                  + "  \"type\":\"rsa\","
                  + "  \"name\":\"this-rsa-has-an-acl\","
                  + "\"value\": {"
                  + "\"public_key\":\"fake-public-key\","
                  + "\"private_key\":\"fake-private-key\""
                  + "},"
                  + "\"access_control_entries\": ["
                  + "{\"actor\": \"app2-guid\","
                  + "\"operations\": [\"read\"]}]"
                  + "}");

          response = mockMvc.perform(put);
        });

        it("sets the ACL for the resource", () -> {
          response.andExpect(status().isOk());
          mockMvc.perform(get("/api/v1/acls?credential_name=this-rsa-has-an-acl"))
              .andExpect(status().isOk())
              .andExpect(jsonPath("$.credential_name").value("/this-rsa-has-an-acl"))
              .andExpect(jsonPath("$.access_control_list[0].actor", equalTo("app2-guid")))
              .andExpect(jsonPath("$.access_control_list[0].operations[0]", equalTo("read")));

        });
      });

      describe("when a ssh set request contains access_control_entries", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder put = put("/api/v1/data")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{"
                  + "  \"type\":\"ssh\","
                  + "  \"name\":\"this-ssh-has-an-acl\","
                  + "\"value\": {"
                  + "\"public_key\":\"fake-public-key\","
                  + "\"private_key\":\"fake-private-key\""
                  + "},"
                  + "\"access_control_entries\": ["
                  + "{\"actor\": \"app2-guid\","
                  + "\"operations\": [\"read\"]}]"
                  + "}");

          response = mockMvc.perform(put);
        });

        it("sets the ACL for the resource", () -> {
          response.andExpect(status().isOk());
          mockMvc.perform(get("/api/v1/acls?credential_name=this-ssh-has-an-acl"))
              .andExpect(status().isOk())
              .andExpect(jsonPath("$.credential_name").value("/this-ssh-has-an-acl"))
              .andExpect(jsonPath("$.access_control_list[0].actor", equalTo("app2-guid")))
              .andExpect(jsonPath("$.access_control_list[0].operations[0]", equalTo("read")));

        });
      });

      describe("when a certificate set request contains access_control_entries", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder put = put("/api/v1/data")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{"
                  + "  \"type\":\"certificate\","
                  + "  \"name\":\"this-certificate-has-an-acl\","
                  + "\"value\": {"
                  + "\"certificate\":\"fake-certificate\","
                  + "\"private_key\":\"fake-private-key\","
                  + "\"ca\":\"fake-ca\""
                  + "},"
                  + "\"access_control_entries\": ["
                  + "{\"actor\": \"app2-guid\","
                  + "\"operations\": [\"read\"]}]"
                  + "}");

          response = mockMvc.perform(put);
        });

        it("sets the ACL for the resource", () -> {
          response.andExpect(status().isOk());
          mockMvc.perform(get("/api/v1/acls?credential_name=this-certificate-has-an-acl"))
              .andExpect(status().isOk())
              .andExpect(jsonPath("$.credential_name").value("/this-certificate-has-an-acl"))
              .andExpect(jsonPath("$.access_control_list[0].actor", equalTo("app2-guid")))
              .andExpect(jsonPath("$.access_control_list[0].operations[0]", equalTo("read")));

        });
      });
    });

    describe("updating a secret", () -> {
      beforeEach(() -> {
        putSecretInDatabase(secretName, "original value");
        resetAuditLogMock();
      });

      it("should return 400 when trying to update a secret with a mismatching type", () -> {
        final MockHttpServletRequestBuilder put = put("/api/v1/data")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            // language=JSON
            .content("{"
                + "  \"type\":\"password\","
                + "  \"name\":\"" + secretName.toUpperCase() + "\","
                + "  \"value\":\"my-password\","
                + "  \"overwrite\":true"
                + "}");
        final String errorMessage = "The credential type cannot be modified."
            + " Please delete the credential if you wish to create it with a different type.";
        mockMvc.perform(put)
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value(errorMessage));
      });

      describe("with the overwrite flag set to true case-insensitively", () -> {
        final String specialValue = "special value";

        beforeEach(() -> {
          fakeTimeSetter.accept(frozenTime.plusSeconds(10).toEpochMilli());

          final MockHttpServletRequestBuilder put = put("/api/v1/data")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{"
                  + "  \"type\":\"value\","
                  + "  \"name\":\"" + secretName.toUpperCase() + "\","
                  + "  \"value\":\"" + specialValue + "\","
                  + "  \"overwrite\":true"
                  + "}");

          response = mockMvc.perform(put);
        });

        it("should return the updated value", () -> {
          ArgumentCaptor<NamedSecret> argumentCaptor = ArgumentCaptor.forClass(NamedSecret.class);

          verify(secretDataService, times(1)).save(argumentCaptor.capture());

          // Because the data service mutates the original entity, the UUID should be set
          // on the original object during the save.
          UUID originalUuid = uuid;
          UUID expectedUuid = argumentCaptor.getValue().getUuid();

          response
              .andExpect(status().isOk())
              .andExpect(jsonPath("$.value").value(specialValue))
              .andExpect(jsonPath("$.id").value(expectedUuid.toString()))
              .andExpect(jsonPath("$.name").value(secretName))
              .andExpect(
                  jsonPath("$.version_created_at").value(frozenTime.plusSeconds(10).toString()));

          assertNotNull(expectedUuid);
          assertThat(expectedUuid, not(equalTo(originalUuid)));
        });

        it("should retain the previous value at the previous id", () -> {
          mockMvc.perform(get("/api/v1/data/" + uuid.toString()))
              .andExpect(status().isOk())
              .andExpect(jsonPath("$.value").value("original value"))
              .andExpect(jsonPath("$.version_created_at").value(frozenTime.toString()));
        });

        it("persists an audit entry", () -> {
          ArgumentCaptor<AuditRecordBuilder> auditRecordParamsCaptor = ArgumentCaptor
              .forClass(AuditRecordBuilder.class);
          verify(auditLogService)
              .performWithAuditing(auditRecordParamsCaptor.capture(), any(Supplier.class));

          assertThat(auditRecordParamsCaptor.getValue().getOperationCode(),
              equalTo(CREDENTIAL_UPDATE));
        });
      });

      describe("with the overwrite flag set to false", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder put = put("/api/v1/data")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{"
                  + "  \"type\":\"value\","
                  + "  \"name\":\"" + secretName + "\","
                  + "  \"value\":\"special value\""
                  + "}");

          response = mockMvc.perform(put);
        });

        it("should return the expected response", () -> {
          response.andExpect(status().isOk())
              .andExpect(jsonPath("$.value").value("original value"));
        });

        it("persists an audit entry", () -> {
          ArgumentCaptor<AuditRecordBuilder> auditRecordParamsCaptor = ArgumentCaptor
              .forClass(AuditRecordBuilder.class);
          verify(auditLogService)
              .performWithAuditing(auditRecordParamsCaptor.capture(), any(Supplier.class));

          assertThat(auditRecordParamsCaptor.getValue().getOperationCode(),
              equalTo(CREDENTIAL_ACCESS));
        });
      });
    });
  }

  private void putSecretInDatabase(String name, String value) throws Exception {
    final MockHttpServletRequestBuilder put = put("/api/v1/data")
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"type\":\"value\","
            + "  \"name\":\"" + name + "\","
            + "  \"value\":\"" + value + "\""
            + "}");

    response = mockMvc.perform(put);

    uuid = secretDataService.findMostRecent(name).getUuid();
    reset(secretDataService);
  }

  private void resetAuditLogMock() throws Exception {
    reset(auditLogService);
    doAnswer(invocation -> {
      final Supplier action = invocation.getArgumentAt(1, Supplier.class);
      return action.get();
    }).when(auditLogService)
        .performWithAuditing(isA(AuditRecordBuilder.class), isA(Supplier.class));
  }
}
