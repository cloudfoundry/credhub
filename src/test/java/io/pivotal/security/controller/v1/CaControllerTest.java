package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.CertificateAuthorityDataService;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.fake.FakeAuditLogService;
import io.pivotal.security.generator.BCCertificateGenerator;
import io.pivotal.security.mapper.CAGeneratorRequestTranslator;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.service.EncryptionKeyService;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.CertificateAuthorityView;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.entity.AuditingOperationCode.CA_ACCESS;
import static io.pivotal.security.entity.AuditingOperationCode.CA_UPDATE;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Supplier;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class CaControllerTest {
  private static final Instant OLDER_FROZEN_TIME_INSTANT = Instant.ofEpochSecond(1300000000L);
  private static final Instant FROZEN_TIME_INSTANT = Instant.ofEpochSecond(1400000000L);
  private static final String VERSION_CREATED_AT_JSON = "\"version_created_at\":\"" + FROZEN_TIME_INSTANT.toString() + "\"";
  private static final String OLDER_VERSION_CREATED_AT_JSON = "\"version_created_at\":\"" + OLDER_FROZEN_TIME_INSTANT.toString() + "\"";
  private static final String CA_CREATION_REQUEST_JSON = "\"type\":\"root\",\"name\":\"%s\",\"value\":{\"certificate\":\"my_cert\",\"private_key\":\"private_key\"}";
  private static final String ANOTHER_CA_CREATION_REQUEST_JSON = "\"type\":\"root\",\"name\":\"%s\",\"value\":{\"certificate\":\"my_cert\",\"private_key\":\"different_private_key\"}";
  private static final String CA_CREATION_RESPONSE_JSON = "\"type\":\"root\",\"value\":{\"certificate\":\"my_cert\",\"private_key\":\"private_key\"}";
  private static final String CA_RESPONSE_JSON = "{" + VERSION_CREATED_AT_JSON + "," + CA_CREATION_RESPONSE_JSON + "}";
  private static final String UNIQUE_NAME = "my-folder/ca-identifier";

  @Autowired
  protected WebApplicationContext context;

  @MockBean
  private CertificateAuthorityDataService certificateAuthorityDataService;

  @Autowired
  CAGeneratorRequestTranslator caGeneratorRequestTranslator;

  @SpyBean
  BCCertificateGenerator certificateGenerator;

  @Autowired
  EncryptionKeyService encryptionKeyService;

  @SpyBean
  FakeAuditLogService auditLogService;
  private MockMvc mockMvc;

  private Consumer<Long> fakeTimeSetter;
  private UUID uuid;
  private NamedCertificateAuthority fakeGeneratedCa;

  private ResultActions response;
  private NamedCertificateAuthority originalCa;
  private NamedCertificateAuthority olderStoredCa;
  private NamedCertificateAuthority storedCa;

  private ResultActions[] responses;

  {
    wireAndUnwire(this, false);
    fakeTimeSetter = mockOutCurrentTimeProvider(this);

    beforeEach(() -> {
      mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
      fakeTimeSetter.accept(FROZEN_TIME_INSTANT.toEpochMilli());

      uuid = UUID.randomUUID();
      fakeGeneratedCa = new NamedCertificateAuthority(UNIQUE_NAME)
          .setType("root")
          .setCertificate("my_cert")
          .setPrivateKey("private_key")
          .setUuid(uuid)
          .setVersionCreatedAt(FROZEN_TIME_INSTANT);
      fakeGeneratedCa.setEncryptionKeyUuid(encryptionKeyService.getActiveEncryptionKeyUuid());
    });

    describe("generating a ca", () -> {
      describe("when creating a new CA", () -> {
        beforeEach(() -> {
          doReturn(new CertificateAuthorityView(fakeGeneratedCa))
              .when(certificateGenerator).generateCertificateAuthority(any(CertificateSecretParameters.class));
          doReturn(
              fakeGeneratedCa
          ).when(certificateAuthorityDataService).save(any(NamedCertificateAuthority.class));
        });

        it("can generate a ca", () -> {
          String requestJson = String.format("{\"type\":\"root\",\"name\":\"%s\",\"parameters\":{\"common_name\":\"test-ca\"}}", UNIQUE_NAME);

          mockMvc.perform(post("/api/v1/ca")
              .content(requestJson)
              .contentType(MediaType.APPLICATION_JSON_UTF8))
              .andExpect(status().isOk())
              .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
              .andExpect(content().json(CA_RESPONSE_JSON));
        });

        it("saves the generated ca in the DB", () -> {
          String requestJson = String.format("{\"type\":\"root\",\"name\":\"%s\",\"parameters\":{\"common_name\":\"test-ca\"}}", UNIQUE_NAME);
          mockMvc.perform(post("/api/v1/ca")
              .content(requestJson)
              .contentType(MediaType.APPLICATION_JSON_UTF8));

          ArgumentCaptor<NamedCertificateAuthority> argumentCaptor = ArgumentCaptor.forClass(NamedCertificateAuthority.class);

          verify(certificateAuthorityDataService, times(1)).save(argumentCaptor.capture());

          NamedCertificateAuthority savedCa = argumentCaptor.getValue();
          assertThat(savedCa.getName(), equalTo(UNIQUE_NAME));
          assertThat(savedCa.getCertificate(), equalTo("my_cert"));
        });

        it("ignores the leading slash in the CA name", () -> {
          String requestJson = String.format(
              "{\"type\":\"root\",\"name\":\"%s\",\"parameters\":{\"common_name\":\"test-ca\"}}",
              "/" + UNIQUE_NAME);

          mockMvc.perform(post("/api/v1/ca")
              .content(requestJson)
              .contentType(MediaType.APPLICATION_JSON_UTF8))
              .andExpect(status().isOk())
              .andExpect(content().json(CA_RESPONSE_JSON));

          ArgumentCaptor<NamedCertificateAuthority> argumentCaptor = ArgumentCaptor.forClass(NamedCertificateAuthority.class);

          verify(certificateAuthorityDataService, times(1)).save(argumentCaptor.capture());

          NamedCertificateAuthority savedCa = argumentCaptor.getValue();
          assertThat(savedCa.getName(), equalTo(UNIQUE_NAME));
        });

        it("returns an error if name is omitted from request body", () -> {
          String requestJson = "{\"type\":\"root\",\"parameters\":{\"common_name\":\"test-ca\"}}";
          mockMvc.perform(post("/api/v1/ca")
              .content(requestJson)
              .contentType(MediaType.APPLICATION_JSON_UTF8))
              .andExpect(status().isBadRequest())
              .andExpect(content().json("{\"error\":\"A CA name must be provided. Please validate your input and retry your request.\"}"));
        });

        it("returns an error if name is empty in request body", () -> {
          String requestJson = "{\"type\":\"root\",\"name\":\"\",\"parameters\":{\"common_name\":\"test-ca\"}}";
          mockMvc.perform(post("/api/v1/ca")
              .content(requestJson)
              .contentType(MediaType.APPLICATION_JSON_UTF8))
              .andExpect(status().isBadRequest())
              .andExpect(content().json("{\"error\":\"A CA name must be provided. Please validate your input and retry your request.\"}"));
        });

        it("creates an audit entry", () -> {
          String requestJson = String.format("{\"type\":\"root\",\"name\": \"%s\",\"parameters\":{\"common_name\":\"test-ca\"}}", UNIQUE_NAME);
          mockMvc.perform(post("/api/v1/ca")
              .content(requestJson)
              .contentType(MediaType.APPLICATION_JSON_UTF8));

          ArgumentCaptor<AuditRecordBuilder> auditRecordParamsCaptor = ArgumentCaptor.forClass(AuditRecordBuilder.class);
          verify(auditLogService).performWithAuditing(auditRecordParamsCaptor.capture(), any(Supplier.class));

          assertThat(auditRecordParamsCaptor.getValue().getOperationCode(), equalTo(CA_UPDATE));
        });
      });

      describe("when the CA already exists in the database", () -> {
        beforeEach(() -> {
          setUpExistingCa();
          setUpCaSaving();

          String requestJson =
              "{" +
                  "\"name\":\"" + UNIQUE_NAME + "\"," +
                  "\"type\":\"root\"," +
                  "\"parameters\":{" +
                  "\"common_name\":\"test-ca\"" +
                  "}" +
                  "}";

          RequestBuilder requestBuilder = post("/api/v1/ca")
              .content(requestJson)
              .contentType(MediaType.APPLICATION_JSON_UTF8);

          response = mockMvc.perform(requestBuilder);
        });

        it("should succeed", () -> {
          response.andExpect(status().isOk())
              .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
              .andExpect(jsonPath("$.value.certificate").isString())
              .andExpect(jsonPath("$.value.private_key").value("new-private-key"))
              .andExpect(jsonPath("$.type").value("root"))
              .andExpect(jsonPath("$.id").value(uuid.toString()))
              .andExpect(jsonPath("$.version_created_at").value(FROZEN_TIME_INSTANT.toString()));
        });

        it("should generate the new certificate", () -> {
          verify(certificateGenerator, times(1)).generateCertificateAuthority(any(CertificateSecretParameters.class));
        });

        it("saves a new CA in the database", () -> {
          ArgumentCaptor<NamedCertificateAuthority> copyArgumentCaptor = ArgumentCaptor.forClass(NamedCertificateAuthority.class);
          ArgumentCaptor<NamedCertificateAuthority> saveArgumentCaptor = ArgumentCaptor.forClass(NamedCertificateAuthority.class);

          verify(originalCa, times(1)).copyInto(copyArgumentCaptor.capture());
          verify(certificateAuthorityDataService, times(1)).save(saveArgumentCaptor.capture());

          NamedCertificateAuthority newCertificateAuthority = saveArgumentCaptor.getValue();
          assertNotNull(newCertificateAuthority.getUuid());
          assertThat(newCertificateAuthority.getUuid(), not(equalTo(originalCa.getUuid())));
          assertNotNull(newCertificateAuthority.getCertificate());
          assertThat(newCertificateAuthority.getCertificate(), not(equalTo(originalCa.getCertificate())));
        });
      });
    });

    it("returns 400 when json keys are invalid", () -> {
      final MockHttpServletRequestBuilder put = put("/api/v1/ca")
          .accept(APPLICATION_JSON)
          .contentType(APPLICATION_JSON)
          .content("{" +
              "  \"type\":\"root\"," +
              "  \"name\":\"test-ca\"," +
              "  \"bogus\":\"value\"" +
              "}");
      mockMvc.perform(put)
          .andExpect(status().isBadRequest())
          .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
          .andExpect(jsonPath("$.error").value("The request includes an unrecognized parameter 'bogus'. Please update or remove this parameter and retry your request."));
    });

    describe("setting CAs in parallel", () -> {
      beforeEach(()->{
        responses = new ResultActions[2];
        uuid = UUID.randomUUID();

        doAnswer(invocation -> {
          NamedCertificateAuthority certificateAuthority = invocation.getArgumentAt(0, NamedCertificateAuthority.class);
          return new NamedCertificateAuthority(certificateAuthority.getName())
              .setType("root")
              .setCertificate("my_cert")
              .setPrivateKey(certificateAuthority.getPrivateKey())
              .setVersionCreatedAt(FROZEN_TIME_INSTANT)
              .setUuid(uuid);
        }).when(certificateAuthorityDataService).save(any(NamedCertificateAuthority.class));

        Thread thread1 = new Thread("thread 1") {
          @Override
          public void run() {
            String requestJson = String.format("{" + CA_CREATION_REQUEST_JSON + "}", UNIQUE_NAME + "1");
            RequestBuilder requestBuilder = put("/api/v1/ca")
                .content(requestJson)
                .contentType(MediaType.APPLICATION_JSON_UTF8);

            try {
              responses[0] = mockMvc.perform(requestBuilder);
            } catch (Exception e) {
              e.printStackTrace();
            }
          }
        };

        Thread thread2 = new Thread("thread 2") {
          @Override
          public void run() {
            String requestJson = String.format("{" + ANOTHER_CA_CREATION_REQUEST_JSON + "}", UNIQUE_NAME + "2");
            RequestBuilder requestBuilder = put("/api/v1/ca")
                .content(requestJson)
                .contentType(MediaType.APPLICATION_JSON_UTF8);

            try {
              responses[1] = mockMvc.perform(requestBuilder);
            } catch (Exception e) {
              e.printStackTrace();
            }
          }
        };

        thread1.start();
        thread2.start();
        thread1.join();
        thread2.join();
      });

      it("test", () -> {
        responses[0].andExpect(jsonPath("$.value.private_key").value("private_key"));
        responses[1].andExpect(jsonPath("$.value.private_key").value("different_private_key"));
      });
    });

    describe("setting a ca", () -> {
      describe("and a name is given with a leading slash", () -> {
        it("should ignore the leading slash", () -> {
          uuid = UUID.randomUUID();
          doReturn(
              new NamedCertificateAuthority(UNIQUE_NAME)
                  .setType("root")
                  .setCertificate("my_cert")
                  .setPrivateKey("private_key")
                  .setVersionCreatedAt(FROZEN_TIME_INSTANT)
                  .setUuid(uuid)
          ).when(certificateAuthorityDataService).save(any(NamedCertificateAuthority.class));

          String requestJson = String.format(
              "{" +
                  "\"type\":\"root\"," +
                  "\"name\":\"%s\"," +
                  "\"value\":{" +
                    "\"certificate\":\"my_cert\"," +
                    "\"private_key\":\"private_key\"" +
                  "}" +
              "}",
              "/" + UNIQUE_NAME);

          mockMvc.perform(put("/api/v1/ca")
              .content(requestJson)
              .contentType(MediaType.APPLICATION_JSON_UTF8))
              .andExpect(status().isOk())
              .andExpect(content().json(CA_RESPONSE_JSON));

          ArgumentCaptor<NamedCertificateAuthority> argumentCaptor = ArgumentCaptor.forClass(NamedCertificateAuthority.class);

          verify(certificateAuthorityDataService, times(1)).save(argumentCaptor.capture());

          NamedCertificateAuthority savedCa = argumentCaptor.getValue();
          assertThat(savedCa.getName(), equalTo(UNIQUE_NAME));
        });
      });

      describe("when creating a new CA", () -> {
        beforeEach(() -> {
          uuid = UUID.randomUUID();
          doReturn(
              new NamedCertificateAuthority(UNIQUE_NAME)
                  .setType("root")
                  .setCertificate("my_cert")
                  .setPrivateKey("private_key")
                  .setVersionCreatedAt(FROZEN_TIME_INSTANT)
                  .setUuid(uuid)
          ).when(certificateAuthorityDataService).save(any(NamedCertificateAuthority.class));
          String requestJson = String.format("{" + CA_CREATION_REQUEST_JSON + "}", UNIQUE_NAME);
          RequestBuilder requestBuilder = put("/api/v1/ca")
              .content(requestJson)
              .contentType(MediaType.APPLICATION_JSON_UTF8);
          response = mockMvc.perform(requestBuilder);
        });

        it("returns the new root ca", () -> {
          response.andExpect(status().isOk())
              .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
              .andExpect(content().json(CA_RESPONSE_JSON));
        });

        it("writes the new root ca to the DB", () -> {
          ArgumentCaptor<NamedCertificateAuthority> argumentCaptor = ArgumentCaptor.forClass(NamedCertificateAuthority.class);
          verify(certificateAuthorityDataService, times(1)).save(argumentCaptor.capture());

          NamedCertificateAuthority actual = argumentCaptor.getValue();

          assertThat(actual.getCertificate(), equalTo("my_cert"));
        });

        it("returns an error if name is omitted from request body", () -> {
          String requestJson = "{\"type\":\"root\",\"value\":{\"certificate\":\"my_cert\",\"private_key\":\"private_key\"}}";
          RequestBuilder requestBuilder = put("/api/v1/ca")
              .content(requestJson)
              .contentType(MediaType.APPLICATION_JSON_UTF8);
          response = mockMvc.perform(requestBuilder)
              .andExpect(status().isBadRequest())
              .andExpect(content().json("{\"error\":\"A CA name must be provided. Please validate your input and retry your request.\"}"));
        });

        it("returns an error if name is empty in request body", () -> {
          String requestJson = String.format("{" + CA_CREATION_REQUEST_JSON + "}", "");
          RequestBuilder requestBuilder = put("/api/v1/ca")
              .content(requestJson)
              .contentType(MediaType.APPLICATION_JSON_UTF8);
          response = mockMvc.perform(requestBuilder)
              .andExpect(status().isBadRequest())
              .andExpect(content().json("{\"error\":\"A CA name must be provided. Please validate your input and retry your request.\"}"));
        });

        it("creates an audit entry", () -> {
          ArgumentCaptor<AuditRecordBuilder> auditRecordParamsCaptor = ArgumentCaptor.forClass(AuditRecordBuilder.class);
          verify(auditLogService).performWithAuditing(auditRecordParamsCaptor.capture(), any(Supplier.class));
          assertThat(auditRecordParamsCaptor.getValue().getOperationCode(), equalTo(CA_UPDATE));
        });
      });

      describe("when updating an existing CA", () -> {
        beforeEach(() -> {
          setUpExistingCa();
          setUpCaSaving();

          String requestJson =
              "{" +
                  "\"type\":\"root\"," +
                  "\"name\":\"" + UNIQUE_NAME + "\"," +
                  "\"value\":{" +
                  "\"certificate\":\"new-certificate\"," +
                  "\"private_key\":\"new-private-key\"" +
                  "}" +
                  "}";

          RequestBuilder requestBuilder = put("/api/v1/ca")
              .content(requestJson)
              .contentType(MediaType.APPLICATION_JSON_UTF8);

          response = mockMvc.perform(requestBuilder);
        });

        it("should succeed", () -> {
          String expectedJson =
              "{" +
                  "\"value\":{" +
                  "\"certificate\":\"new-certificate\"," +
                  "\"private_key\":\"new-private-key\"" +
                  "}," +
                  "\"type\":\"root\"," +
                  "\"id\":\"" + uuid.toString() + "\"," +
                  VERSION_CREATED_AT_JSON +
                  "}";
          response
              .andExpect(status().isOk())
              .andExpect(content().json(expectedJson, true));
        });

        it("should create a new entity for it", () -> {
          ArgumentCaptor<NamedCertificateAuthority> copyArgumentCaptor = ArgumentCaptor.forClass(NamedCertificateAuthority.class);
          ArgumentCaptor<NamedCertificateAuthority> saveArgumentCaptor = ArgumentCaptor.forClass(NamedCertificateAuthority.class);

          verify(originalCa, times(1)).copyInto(copyArgumentCaptor.capture());
          verify(certificateAuthorityDataService, times(1)).save(saveArgumentCaptor.capture());

          NamedCertificateAuthority newCertificateAuthority = saveArgumentCaptor.getValue();
          assertNotNull(newCertificateAuthority.getUuid());
          assertThat(newCertificateAuthority.getUuid(), not(equalTo(originalCa.getUuid())));
          assertThat(newCertificateAuthority.getCertificate(), equalTo("new-certificate"));
        });

        it("creates an audit record", () -> {
          ArgumentCaptor<AuditRecordBuilder> auditRecordParamsCaptor = ArgumentCaptor.forClass(AuditRecordBuilder.class);
          verify(auditLogService).performWithAuditing(auditRecordParamsCaptor.capture(), any(Supplier.class));

          assertThat(auditRecordParamsCaptor.getValue().getOperationCode(), equalTo(CA_UPDATE));
        });
      });
    });

    describe("errors when setting a CA", () -> {
      it("put with only a certificate returns an error", () -> {
        requestWithError("{\"type\":\"root\",\"name\":\"error1\",\"value\":{\"certificate\":\"my_certificate\"}}");
      });

      it("put with only private returns an error", () -> {
        requestWithError("{\"type\":\"root\",\"name\":\"error2\",\"value\":{\"private_key\":\"my_private_key\"}}");
      });

      it("put without keys returns an error", () -> {
        requestWithError("{\"type\":\"root\",\"name\":\"error3\",\"value\":{}}");
      });

      it("put with empty request returns an error", () -> {
        requestWithError("{\"type\":\"root\",\"name\":\"error4\"}");
      });

      it("put cert with garbage returns an error", () -> {
        String requestJson = "{\"value\":\"\",\"name\":\"error5\"}";

        RequestBuilder requestBuilder = put("/api/v1/ca")
            .content(requestJson)
            .contentType(MediaType.APPLICATION_JSON_UTF8);

        mockMvc.perform(requestBuilder)
            .andExpect(status().isBadRequest());
      });
    });

    describe("getting a ca", () -> {
      beforeEach(() -> {
        uuid = UUID.randomUUID();
        olderStoredCa = new NamedCertificateAuthority(UNIQUE_NAME)
            .setType("root")
            .setCertificate("my-certificate-old")
            .setPrivateKey("my-priv")
            .setUuid(uuid)
            .setVersionCreatedAt(OLDER_FROZEN_TIME_INSTANT);
        uuid = UUID.randomUUID();
        storedCa = new NamedCertificateAuthority(UNIQUE_NAME)
            .setType("root")
            .setCertificate("my-certificate")
            .setPrivateKey("my-priv")
            .setUuid(uuid)
            .setVersionCreatedAt(FROZEN_TIME_INSTANT);
        doReturn(newArrayList(storedCa, olderStoredCa)).when(certificateAuthorityDataService).findAllByName(eq(UNIQUE_NAME));
        doReturn(storedCa).when(certificateAuthorityDataService).findMostRecent(eq(UNIQUE_NAME));
      });

      describe("by name", () -> {
        describe("as a query parameter", () -> {
          it("returns the ca when the name is a request parameter", () -> {
            String expectedJsonWithManyCAs = "{ \"data\": [" +
                "{"
                + VERSION_CREATED_AT_JSON + "," +
                "    \"type\":\"root\"," +
                "    \"value\":{" +
                "        \"certificate\":\"my-certificate\"," +
                "        \"private_key\":\"my-priv\"" +
                "    }," +
                "    \"id\":\"" + storedCa.getUuid().toString() + "\"" +
                "}," +
                "{"
                + OLDER_VERSION_CREATED_AT_JSON + "," +
                "    \"type\":\"root\"," +
                "    \"value\":{" +
                "        \"certificate\":\"my-certificate-old\"," +
                "        \"private_key\":\"my-priv\"" +
                "    }," +
                "    \"id\":\"" + olderStoredCa.getUuid().toString() + "\"" +
                "}" +
                "]" +
                "}";

            mockMvc.perform(get("/api/v1/ca?name=" + UNIQUE_NAME))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
                .andExpect(content().json(expectedJsonWithManyCAs, true));
          });

          describe("ignoring a leading slash in the name of the CA", () -> {

            it("returns the ca when the name is a request parameter", () -> {
              String expectedJsonWithManyCAs = "{ \"data\": [" +
                  "{"
                  + VERSION_CREATED_AT_JSON + "," +
                  "    \"type\":\"root\"," +
                  "    \"value\":{" +
                  "        \"certificate\":\"my-certificate\"," +
                  "        \"private_key\":\"my-priv\"" +
                  "    }," +
                  "    \"id\":\"" + storedCa.getUuid().toString() + "\"" +
                  "}," +
                  "{"
                  + OLDER_VERSION_CREATED_AT_JSON + "," +
                  "    \"type\":\"root\"," +
                  "    \"value\":{" +
                  "        \"certificate\":\"my-certificate-old\"," +
                  "        \"private_key\":\"my-priv\"" +
                  "    }," +
                  "    \"id\":\"" + olderStoredCa.getUuid().toString() + "\"" +
                  "}" +
                  "]" +
                  "}";

              mockMvc.perform(get("/api/v1/ca?name=" + "/" + UNIQUE_NAME))
                  .andExpect(status().isOk())
                  .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
                  .andExpect(content().json(expectedJsonWithManyCAs, true));
            });

            it("can limit results with the 'current' query parameter", () -> {
              String jsonWithOnlyOneCA = "{ \"data\": [" +
                  "{"
                  + VERSION_CREATED_AT_JSON + "," +
                  "    \"type\":\"root\"," +
                  "    \"value\":{" +
                  "        \"certificate\":\"my-certificate\"," +
                  "        \"private_key\":\"my-priv\"" +
                  "    }," +
                  "    \"id\":\"" + storedCa.getUuid().toString() + "\"" +
                  "}]" +
                  "}";

              String requestUrl = "/api/v1/ca?name=" + "/" + UNIQUE_NAME + "&current=true";
              mockMvc.perform(get(requestUrl))
                  .andExpect(status().isOk())
                  .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
                  .andExpect(content().json(jsonWithOnlyOneCA, true));
            });
          });

          it("can limit results with the 'current' query parameter", () -> {
            String jsonWithOnlyOneCA = "{ \"data\": [" +
                "{"
                + VERSION_CREATED_AT_JSON + "," +
                "    \"type\":\"root\"," +
                "    \"value\":{" +
                "        \"certificate\":\"my-certificate\"," +
                "        \"private_key\":\"my-priv\"" +
                "    }," +
                "    \"id\":\"" + storedCa.getUuid().toString() + "\"" +
                "}]" +
                "}";

            String requestUrl = String.format("/api/v1/ca?name=%s&current=true", UNIQUE_NAME);
            mockMvc.perform(get(requestUrl))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
                .andExpect(content().json(jsonWithOnlyOneCA, true));
          });

          it("returns the all results when the 'current' query parameter is false'", () -> {
            String expectedJsonWithManyCAs = "{ \"data\": [" +
                "{"
                + VERSION_CREATED_AT_JSON + "," +
                "    \"type\":\"root\"," +
                "    \"value\":{" +
                "        \"certificate\":\"my-certificate\"," +
                "        \"private_key\":\"my-priv\"" +
                "    }," +
                "    \"id\":\"" + storedCa.getUuid().toString() + "\"" +
                "}," +
                "{"
                + OLDER_VERSION_CREATED_AT_JSON + "," +
                "    \"type\":\"root\"," +
                "    \"value\":{" +
                "        \"certificate\":\"my-certificate-old\"," +
                "        \"private_key\":\"my-priv\"" +
                "    }," +
                "    \"id\":\"" + olderStoredCa.getUuid().toString() + "\"" +
                "}" +
                "]" +
                "}";

            String requestUrl = String.format("/api/v1/ca?name=%s&current=false", UNIQUE_NAME);
            mockMvc.perform(get(requestUrl))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
                .andExpect(content().json(expectedJsonWithManyCAs, true));
          });

          it("handles empty 'current' parameter as false", () -> {
            String expectedJsonWithManyCAs = "{ \"data\": [" +
                "{"
                + VERSION_CREATED_AT_JSON + "," +
                "    \"type\":\"root\"," +
                "    \"value\":{" +
                "        \"certificate\":\"my-certificate\"," +
                "        \"private_key\":\"my-priv\"" +
                "    }," +
                "    \"id\":\"" + storedCa.getUuid().toString() + "\"" +
                "}," +
                "{"
                + OLDER_VERSION_CREATED_AT_JSON + "," +
                "    \"type\":\"root\"," +
                "    \"value\":{" +
                "        \"certificate\":\"my-certificate-old\"," +
                "        \"private_key\":\"my-priv\"" +
                "    }," +
                "    \"id\":\"" + olderStoredCa.getUuid().toString() + "\"" +
                "}" +
                "]" +
                "}";

            String requestUrl = String.format("/api/v1/ca?name=%s&current=", UNIQUE_NAME);
            mockMvc.perform(get(requestUrl))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
                .andExpect(content().json(expectedJsonWithManyCAs, true));
          });

          it("handles empty name", () -> {
            mockMvc.perform(get("/api/v1/ca?name="))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Missing identifier. Please validate your input and retry your request."));
          });

          it("persists an audit entry when getting a ca", () -> {
            mockMvc.perform(get("/api/v1/ca?name=" + UNIQUE_NAME))
                .andExpect(status().isOk());
            ArgumentCaptor<AuditRecordBuilder> auditRecordParamsCaptor = ArgumentCaptor.forClass(AuditRecordBuilder.class);
            verify(auditLogService).performWithAuditing(auditRecordParamsCaptor.capture(), any(Supplier.class));

            assertThat(auditRecordParamsCaptor.getValue().getOperationCode(), equalTo(CA_ACCESS));
          });
        });
      });

      describe("when there are previous versions of a named key", () -> {
        it("returns all the versions", () -> {
          doReturn(newArrayList(fakeGeneratedCa, storedCa))
              .when(certificateAuthorityDataService).findAllByName(eq(UNIQUE_NAME));
          mockMvc.perform(get("/api/v1/ca?name=" + UNIQUE_NAME))
              .andExpect(status().isOk())
              .andExpect(jsonPath("$.data").value(hasSize(2)))
              .andExpect(jsonPath("$.data[0].value.certificate").value("my_cert"))
              .andExpect(jsonPath("$.data[1].value.certificate").value("my-certificate"));
        });
      });
    });

    describe("by id", () -> {
      beforeEach(() -> {
        storedCa = new NamedCertificateAuthority(UNIQUE_NAME)
            .setType("root")
            .setCertificate("my-certificate")
            .setPrivateKey("my-priv")
            .setUuid(uuid)
            .setVersionCreatedAt(FROZEN_TIME_INSTANT);
        doReturn(storedCa)
            .when(certificateAuthorityDataService)
            .findByUuid(eq("my-uuid"));

        MockHttpServletRequestBuilder get = get("/api/v1/ca/my-uuid")
            .accept(APPLICATION_JSON);

        response = mockMvc.perform(get);
      });

      it("returns the ca", () -> {
        String expectedJson = "{" + VERSION_CREATED_AT_JSON + "," +
            "    \"type\":\"root\"," +
            "    \"value\":{" +
            "        \"certificate\":\"my-certificate\"," +
            "        \"private_key\":\"my-priv\"" +
            "    }," +
            "    \"id\":\"" + storedCa.getUuid().toString() + "\"" +
            "}";

        response.andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
            .andExpect(content().json(expectedJson, true));
      });

      it("handles empty id", () -> {
        mockMvc.perform(get("/api/v1/ca/"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("Missing identifier. Please validate your input and retry your request."));
      });

      it("persists an audit entry when getting a ca", () -> {
        ArgumentCaptor<AuditRecordBuilder> auditRecordParamsCaptor = ArgumentCaptor.forClass(AuditRecordBuilder.class);
        verify(auditLogService).performWithAuditing(auditRecordParamsCaptor.capture(), any(Supplier.class));

        assertThat(auditRecordParamsCaptor.getValue().getOperationCode(), equalTo(CA_ACCESS));
        assertThat(auditRecordParamsCaptor.getValue().getCredentialName(), equalTo(UNIQUE_NAME));
      });
    });

    it("returns bad request for PUT with invalid type", () -> {
      String uuid = UUID.randomUUID().toString();
      String requestJson = "{\"type\":" + uuid + ",\"name\":\"" + UNIQUE_NAME + "\",\"value\":{\"certificate\":\"my_cert\",\"private_key\":\"private_key\"}}";

      String invalidTypeJson = "{\"error\": \"The request does not include a valid type. Please validate your input and retry your request.\"}";
      RequestBuilder requestBuilder = put("/api/v1/ca")
          .content(requestJson)
          .contentType(MediaType.APPLICATION_JSON_UTF8);

      mockMvc.perform(requestBuilder)
          .andExpect(status().isBadRequest())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
          .andExpect(content().json(invalidTypeJson));
    });

    it("returns bad request for generate POST with invalid type", () -> {
      String requestJson = "{\"name\":\"" + UNIQUE_NAME + "\",\"type\":\"invalid-type\"}";

      String invalidTypeJson = "{\"error\": \"The request does not include a valid type. Please validate your input and retry your request.\"}";
      RequestBuilder requestBuilder = post("/api/v1/ca")
          .content(requestJson)
          .contentType(MediaType.APPLICATION_JSON_UTF8);

      mockMvc.perform(requestBuilder)
          .andExpect(status().isBadRequest())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
          .andExpect(content().json(invalidTypeJson));
    });

    describe("when CA does not exist", () -> {
      beforeEach(() -> {
        RequestBuilder get = get("/api/v1/ca/some-id");
        response = mockMvc.perform(get);
      });

      it("get returns 404 when not found", () -> {
        String notFoundJson = "{\"error\": \"CA not found. Please validate your input and retry your request.\"}";
        response
            .andExpect(status().isNotFound())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
            .andExpect(content().json(notFoundJson));
      });

      it("does not record name in the audit log table", () -> {
        ArgumentCaptor<AuditRecordBuilder> auditRecordParamsCaptor = ArgumentCaptor.forClass(AuditRecordBuilder.class);
        verify(auditLogService).performWithAuditing(auditRecordParamsCaptor.capture(), any(Supplier.class));

        assertNull(auditRecordParamsCaptor.getValue().getCredentialName());
      });
    });
  }

  private void requestWithError(String requestJson) throws Exception {
    String notFoundJson = "{\"error\":\"All keys are required to set a CA. Please validate your input and retry your request.\"}";

    RequestBuilder requestBuilder = put("/api/v1/ca")
        .content(requestJson)
        .contentType(MediaType.APPLICATION_JSON_UTF8);

    mockMvc.perform(requestBuilder)
        .andExpect(status().isBadRequest())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(notFoundJson));
  }

  private void setUpExistingCa() {
    originalCa = spy(new NamedCertificateAuthority(UNIQUE_NAME));
    originalCa.setUuid(UUID.randomUUID());
    originalCa.setCertificate("original-certificate");
    originalCa.setEncryptionKeyUuid(encryptionKeyService.getActiveEncryptionKeyUuid());

    doReturn(originalCa)
        .when(certificateAuthorityDataService).findMostRecent(anyString());
  }

  private void setUpCaSaving() {
    uuid = UUID.randomUUID();

    doAnswer(invocation -> {
      NamedCertificateAuthority certificateAuthority = invocation.getArgumentAt(0, NamedCertificateAuthority.class);
      certificateAuthority.setEncryptionKeyUuid(encryptionKeyService.getActiveEncryptionKeyUuid());
      certificateAuthority.setVersionCreatedAt(FROZEN_TIME_INSTANT);
      if (certificateAuthority.getUuid() == null) {
        certificateAuthority.setUuid(uuid);
      }
      return certificateAuthority.setPrivateKey("new-private-key");
    }).when(certificateAuthorityDataService).save(any(NamedCertificateAuthority.class));
  }
}
