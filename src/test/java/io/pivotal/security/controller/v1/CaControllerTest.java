package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.mapper.CAGeneratorRequestTranslator;
import io.pivotal.security.repository.CertificateAuthorityRepository;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.view.CertificateAuthority;
import io.pivotal.security.view.ParameterizedValidationException;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Consumer;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.*;
import static org.exparity.hamcrest.BeanMatchers.theSameAs;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.*;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@WebAppConfiguration
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class CaControllerTest {

  @Autowired
  protected WebApplicationContext context;

  @Autowired
  private SecretRepository secretRepository;

  @Autowired
  private CertificateAuthorityRepository caRepository;

  @InjectMocks
  @Autowired
  private CaController caController;

  @Mock
  CAGeneratorRequestTranslator caGeneratorRequestTranslator;

  private MockMvc mockMvc;
  private Instant frozenTime = Instant.ofEpochSecond(1400000000L);
  private Consumer<Long> fakeTimeSetter;

  private String uniqueName;
  private String urlPath;

  private static final String CA_CREATION_JSON = "\"type\":\"root\",\"value\":{\"certificate\":\"my_cert\",\"private_key\":\"private_key\"}";

  {
    wireAndUnwire(this);
    fakeTimeSetter = mockOutCurrentTimeProvider(this);

    beforeEach(() -> {
      mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
      fakeTimeSetter.accept(frozenTime.toEpochMilli());
      uniqueName = "my-folder/ca-identifier";
      urlPath = "/api/v1/ca/" + uniqueName;
    });

    it("can generate a ca", () -> {
      doAnswer(invocation -> {
        final NamedCertificateAuthority namedCertificateAuthority = invocation.getArgumentAt(0, NamedCertificateAuthority.class);
        namedCertificateAuthority.setType("root");
        namedCertificateAuthority.setCertificate("my_cert");
        namedCertificateAuthority.setPrivateKey("private_key");
        return null;
      }).when(caGeneratorRequestTranslator).populateEntityFromJson(isA(NamedCertificateAuthority.class), isA(DocumentContext.class));

      String requestJson = "{\"type\":\"root\"}";
      String responseJson = "{" + getUpdatedAtJson() + "," + CA_CREATION_JSON + "}";

      NamedCertificateAuthority entity =
          new NamedCertificateAuthority(uniqueName)
              .setUpdatedAt(frozenTime)
              .setType("root")
              .setCertificate("my_cert")
              .setPrivateKey("private_key");
      RequestBuilder requestBuilder = postRequestBuilder(urlPath, requestJson);

      mockMvc.perform(requestBuilder)
          .andExpect(status().isOk())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
          .andExpect(content().json(responseJson));

      verify(caGeneratorRequestTranslator).validateJsonKeys(any(DocumentContext.class));
      NamedCertificateAuthority oneByName = caRepository.findOneByNameIgnoreCase(uniqueName);
      assertThat(oneByName, theSameAs(entity).excludeProperty("Id").excludeProperty("Nonce").excludeProperty("EncryptedValue"));
      assertThat(secretRepository.findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(uniqueName), nullValue());
    });

    describe("setter", () -> {
      it("can set a root ca", () -> {
        String requestJson = "{" + CA_CREATION_JSON + "}";
        String responseJson = "{" + getUpdatedAtJson() + "," + CA_CREATION_JSON + "}";

        RequestBuilder requestBuilder = putRequestBuilder(urlPath, requestJson);

        mockMvc.perform(requestBuilder)
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
            .andExpect(content().json(responseJson));

        CertificateAuthority expected = new CertificateAuthority("root", "my_cert", "private_key");
        expected.setUpdatedAt(frozenTime);
        assertThat(CertificateAuthority.fromEntity(caRepository.findOneByNameIgnoreCase(uniqueName)), theSameAs(expected));
        assertThat(secretRepository.findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(uniqueName), nullValue());
      });

      it("can overwrite a root ca case-independently", () -> {
        String requestJson = "{" + CA_CREATION_JSON + "}";
        String responseJson = "{" + getUpdatedAtJson() + "," + CA_CREATION_JSON + "}";

        RequestBuilder requestBuilder = putRequestBuilder("/api/v1/ca/" + uniqueName.toUpperCase(), requestJson);

        mockMvc.perform(requestBuilder)
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
            .andExpect(content().json(responseJson));

        CertificateAuthority expected = new CertificateAuthority("root", "my_cert", "private_key");
        expected.setUpdatedAt(frozenTime);
        assertThat(CertificateAuthority.fromEntity(caRepository.findOneByNameIgnoreCase(uniqueName)), theSameAs(expected));
        assertThat(secretRepository.findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(uniqueName), nullValue());

        String jsonContent = "\"type\":\"root\",\"value\":{\"certificate\":\"my_cert2\",\"private_key\":\"private_key2\"}";
        requestJson = "{" + jsonContent + "}";
        responseJson = "{" + getUpdatedAtJson() + "," + jsonContent + "}";
        requestBuilder = putRequestBuilder(urlPath, requestJson);
        mockMvc.perform(requestBuilder)
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
            .andExpect(content().json(responseJson));

        expected = new CertificateAuthority("root", "my_cert2", "private_key2");
        expected.setUpdatedAt(frozenTime);
        assertThat(CertificateAuthority.fromEntity(caRepository.findOneByNameIgnoreCase(uniqueName)), theSameAs(expected));
        assertThat(secretRepository.findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(uniqueName), nullValue());
      });
    });

    it("can fetch a root ca", () -> {
      NamedCertificateAuthority certificateSecret = new NamedCertificateAuthority(uniqueName)
          .setType("root")
          .setCertificate("get-certificate")
          .setPrivateKey("get-priv");
      caRepository.save(certificateSecret);

      String expectedJson = "{" + getUpdatedAtJson() + ",\"type\":\"root\",\"value\":{\"certificate\":\"get-certificate\",\"private_key\":\"get-priv\"}}";
      mockMvc.perform(get(urlPath))
          .andExpect(status().isOk())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
          .andExpect(content().json(expectedJson));
    });

    it("returns bad request for PUT with invalid type", () -> {
      String uuid = UUID.randomUUID().toString();
      String requestJson = "{\"type\":" + uuid + ",\"value\":{\"certificate\":\"my_cert\",\"private_key\":\"private_key\"}}";

      String invalidTypeJson = "{\"error\": \"The request does not include a valid type. Please validate your input and retry your request.\"}";
      RequestBuilder requestBuilder = putRequestBuilder(urlPath, requestJson);

      mockMvc.perform(requestBuilder)
          .andExpect(status().isBadRequest())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
          .andExpect(content().json(invalidTypeJson));
    });

    it("returns bad request for generate POST with invalid type", () -> {
      doThrow(new ParameterizedValidationException("error.bad_authority_type"))
          .when(caGeneratorRequestTranslator)
          .populateEntityFromJson(any(NamedCertificateAuthority.class), any(DocumentContext.class));
      String uuid = UUID.randomUUID().toString();
      String requestJson = "{\"type\":" + uuid + "}";

      String invalidTypeJson = "{\"error\": \"The request does not include a valid type. Please validate your input and retry your request.\"}";
      RequestBuilder requestBuilder = postRequestBuilder(urlPath, requestJson);

      mockMvc.perform(requestBuilder)
          .andExpect(status().isBadRequest())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
          .andExpect(content().json(invalidTypeJson));
    });

    it("can get a certificate authority case-independently", () -> {
      String responseJson = "{" + getUpdatedAtJson() + ",\"type\":\"root\",\"value\":{\"certificate\":\"my_certificate\",\"private_key\":\"my_private_key\"}}";
      NamedCertificateAuthority namedCertificateAuthority = new NamedCertificateAuthority("my_name");
      namedCertificateAuthority.setType("root");
      namedCertificateAuthority.setCertificate("my_certificate");
      namedCertificateAuthority.setPrivateKey("my_private_key");
      caRepository.save(namedCertificateAuthority);

      RequestBuilder requestBuilder = getRequestBuilder("/api/v1/ca/MY_NAME");
      mockMvc.perform(requestBuilder)
          .andExpect(status().isOk())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
          .andExpect(content().json(responseJson));
    });

    it("can put a certificate authority twice", () -> {
      String requestJson = "{\"type\":\"root\",\"value\":{\"certificate\":\"my_certificate\",\"private_key\":\"priv\"}}";
      String requestJson2 = "{\"type\":\"root\",\"value\":{\"certificate\":\"my_certificate_2\",\"private_key\":\"priv_2\"}}";

      RequestBuilder requestBuilder = putRequestBuilder(urlPath, requestJson);
      mockMvc.perform(requestBuilder)
          .andExpect(status().isOk())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
          .andExpect(content().json(requestJson));

      RequestBuilder requestBuilder2 = putRequestBuilder(urlPath, requestJson2);
      mockMvc.perform(requestBuilder2)
          .andExpect(status().isOk())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
          .andExpect(content().json(requestJson2));

      CertificateAuthority expected = new CertificateAuthority("root", "my_certificate_2", "priv_2");
      NamedCertificateAuthority saved = caRepository.findOneByNameIgnoreCase(uniqueName);
      assertThat(new CertificateAuthority(saved.getType(), saved.getCertificate(), saved.getPrivateKey()), theSameAs(expected));
    });

    it("get returns 404 when not found", () -> {
      String notFoundJson = "{\"error\": \"CA not found. Please validate your input and retry your request.\"}";

      RequestBuilder requestBuilder = getRequestBuilder(urlPath);

      mockMvc.perform(requestBuilder)
          .andExpect(status().isNotFound())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
          .andExpect(content().json(notFoundJson));
    });

    it("put with only a certificate returns an error", () -> {
      requestWithError("{\"type\":\"root\",\"root\":{\"certificate\":\"my_certificate\"}}");
    });

    it("put with only private returns an error", () -> {
      requestWithError("{\"type\":\"root\",\"root\":{\"private_key\":\"my_private_key\"}}");
    });

    it("put without keys returns an error", () -> {
      requestWithError("{\"type\":\"root\",\"root\":{}}");
    });

    it("put with empty request returns an error", () -> {
      requestWithError("{\"type\":\"root\"}");
    });

    it("put cert with garbage returns an error", () -> {
      String requestJson = "{\"root\": }";

      RequestBuilder requestBuilder = putRequestBuilder(urlPath, requestJson);

      mockMvc.perform(requestBuilder)
          .andExpect(status().isBadRequest());
    });

    it("returns a parameterized error message for an invalid key", () -> {
      doThrow(new ParameterizedValidationException("error.invalid_json_key", newArrayList("foo error")))
      .when(caGeneratorRequestTranslator).validateJsonKeys(isA(DocumentContext.class));

      RequestBuilder requestBuilder = postRequestBuilder(urlPath, "{\"type\":\"root\",\"value\":{\"certificate\":\"my_certificate\",\"private_key\":\"my_private_key\"}}");

      mockMvc.perform(requestBuilder)
          .andExpect(status().isBadRequest())
          .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
          .andExpect(jsonPath("$.error").value("The request includes an unrecognized parameter 'foo error'. Please update or remove this parameter and retry your request."));
    });
  }

  private void requestWithError(String requestJson) throws Exception {
    String notFoundJson = "{\"error\": \"All keys are required to set a CA. Please validate your input and retry your request.\"}";

    RequestBuilder requestBuilder = putRequestBuilder(urlPath, requestJson);

    mockMvc.perform(requestBuilder)
        .andExpect(status().isBadRequest())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(notFoundJson));
  }

  private RequestBuilder getRequestBuilder(String path) {
    return get(path)
        .contentType(MediaType.APPLICATION_JSON_UTF8);
  }

  private RequestBuilder putRequestBuilder(String path, String requestBody) {
    return put(path)
        .content(requestBody)
        .contentType(MediaType.APPLICATION_JSON_UTF8);
  }

  private RequestBuilder postRequestBuilder(String path, String requestBody) {
    return post(path)
        .content(requestBody)
        .contentType(MediaType.APPLICATION_JSON_UTF8);
  }

  private String getUpdatedAtJson() {
    return "\"updated_at\":\"2014-05-13T16:53:20Z\"";
  }
}
