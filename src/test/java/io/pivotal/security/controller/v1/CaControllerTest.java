package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.generator.SignedCertificateGenerator;
import io.pivotal.security.mapper.CertificateAuthorityRequestTranslatorWithGeneration;
import io.pivotal.security.repository.InMemoryAuthorityRepository;
import io.pivotal.security.repository.InMemorySecretRepository;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.view.CertificateAuthority;
import io.pivotal.security.view.CertificateSecret;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.exparity.hamcrest.BeanMatchers;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.MediaType;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import sun.security.x509.X509CertImpl;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.autoTransactional;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static java.time.format.DateTimeFormatter.ofPattern;
import static org.exparity.hamcrest.BeanMatchers.theSameAs;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.UUID;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@WebAppConfiguration
public class CaControllerTest {

  @Autowired
  protected WebApplicationContext context;

  @Autowired
  private InMemorySecretRepository secretRepository;

  @Autowired
  private InMemoryAuthorityRepository caRepository;

  @InjectMocks
  @Autowired
  private CaController caController;

  @Autowired
  @Qualifier("currentTimeProvider")
  CurrentTimeProvider currentTimeProvider;

  @Mock
  CertificateAuthorityRequestTranslatorWithGeneration requestTranslatorWithGeneration;

  private MockMvc mockMvc;

  private final ZoneId utc = ZoneId.of("UTC");
  private LocalDateTime frozenTime;

  {
    wireAndUnwire(this);
    autoTransactional(this);

    beforeEach(() -> {
      freeze();
      mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
    });

    afterEach(() -> {
      currentTimeProvider.reset();
    });

    // TODO updated-at JSON
    it("can generate a ca", () -> {
      String requestJson = "{\"type\":\"root\"}";
      String responseJson = "{\"type\":\"root\",\"ca\":{\"certificate\":\"my_cert\",\"private\":\"private_key\"}}";

      CertificateAuthority certificateAuthority = new CertificateAuthority("root", "my_cert", "private_key");
      when(requestTranslatorWithGeneration.createAuthorityFromJson(any(DocumentContext.class))).thenReturn(certificateAuthority);
      RequestBuilder requestBuilder = postRequestBuilder("/api/v1/ca/generated-ca-identifier", requestJson);

      mockMvc.perform(requestBuilder)
          .andExpect(status().isOk())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
          .andExpect(content().json(responseJson));
      assertThat(caRepository.findOneByName("generated-ca-identifier").generateView(), theSameAs(certificateAuthority));
      assertThat(secretRepository.findOneByName("generated-ca-identifier"), nullValue());
    });

    it("can set a root ca", () -> {
      String requestJson = "{" + getUpdatedAtJson() + ",\"type\":\"root\",\"ca\":{\"certificate\":\"my_cert\",\"private\":\"private_key\"}}";

      RequestBuilder requestBuilder = putRequestBuilder("/api/v1/ca/ca-identifier", requestJson);

      mockMvc.perform(requestBuilder)
          .andExpect(status().isOk())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
          .andExpect(content().json(requestJson));

      CertificateAuthority expected = new CertificateAuthority("root", "my_cert", "private_key");
      expected.setUpdatedAt(frozenTime);
      assertThat(caRepository.findOneByName("ca-identifier").generateView(), theSameAs(expected));
      assertThat(secretRepository.findOneByName("ca-identifier"), nullValue());
    });

    it("returns bad request for invalid type", () -> {
      String uuid = UUID.randomUUID().toString();
      String requestJson = "{\"type\":" + uuid + ",\"ca\":{\"certificate\":\"my_cert\",\"private\":\"private_key\"}}";

      String invalidTypeJson = "{\"error\": \"The request does not include a valid type. Please validate your input and retry your request.\"}";
      RequestBuilder requestBuilder = putRequestBuilder("/api/v1/ca/ca-identifier", requestJson);

      mockMvc.perform(requestBuilder)
          .andExpect(status().isBadRequest())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
          .andExpect(content().json(invalidTypeJson));
    });

    it("can get a certificate authority", () -> {
      String responseJson = "{" + getUpdatedAtJson() + ",\"type\":\"root\",\"ca\":{\"certificate\":\"my_certificate\",\"private\":\"my_private_key\"}}";
      NamedCertificateAuthority namedCertificateAuthority = new NamedCertificateAuthority("my_name");
      namedCertificateAuthority.setType("root");
      namedCertificateAuthority.setCertificate("my_certificate");
      namedCertificateAuthority.setPrivateKey("my_private_key");
      caRepository.save(namedCertificateAuthority);

      RequestBuilder requestBuilder = getRequestBuilder("/api/v1/ca/my_name");
      mockMvc.perform(requestBuilder)
          .andExpect(status().isOk())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
          .andExpect(content().json(responseJson));
    });

    it("can put a certificate authority twice", () -> {
      String requestJson = "{\"type\":\"root\",\"ca\":{\"certificate\":\"my_certificate\",\"private\":\"priv\"}}";
      String requestJson2 = "{\"type\":\"root\",\"ca\":{\"certificate\":\"my_certificate_2\",\"private\":\"priv_2\"}}";

      RequestBuilder requestBuilder = putRequestBuilder("/api/v1/ca/ca-identifier", requestJson);
      mockMvc.perform(requestBuilder)
          .andExpect(status().isOk())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
          .andExpect(content().json(requestJson));

      RequestBuilder requestBuilder2 = putRequestBuilder("/api/v1/ca/ca-identifier", requestJson2);
      mockMvc.perform(requestBuilder2)
          .andExpect(status().isOk())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
          .andExpect(content().json(requestJson2));

      CertificateAuthority expected = new CertificateAuthority("root", "my_certificate_2", "priv_2");
      NamedCertificateAuthority saved = (NamedCertificateAuthority) caRepository.findOneByName("ca-identifier");
      assertThat(new CertificateAuthority(saved.getType(), saved.getCertificate(), saved.getPrivateKey()), theSameAs(expected));
    });

    it("get returns 404 when not found", () -> {
      String notFoundJson = "{\"error\": \"CA not found. Please validate your input and retry your request.\"}";

      RequestBuilder requestBuilder = getRequestBuilder("/api/v1/ca/my_name");

      mockMvc.perform(requestBuilder)
          .andExpect(status().isNotFound())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
          .andExpect(content().json(notFoundJson));
    });

    it("put with only a certificate returns an error", () -> {
      String requestJson = "{\"type\":\"root\",\"root\":{\"certificate\":\"my_certificate\"}}";
      String notFoundJson = "{\"error\": \"All keys are required to set a CA. Please validate your input and retry your request.\"}";

      RequestBuilder requestBuilder = putRequestBuilder("/api/v1/ca/ca-identifier", requestJson);

      mockMvc.perform(requestBuilder)
          .andExpect(status().isBadRequest())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
          .andExpect(content().json(notFoundJson));
    });

    it("put with only private returns an error", () -> {
      String requestJson = "{\"type\":\"root\",\"root\":{\"private\":\"my_private_key\"}}";
      String notFoundJson = "{\"error\": \"All keys are required to set a CA. Please validate your input and retry your request.\"}";

      RequestBuilder requestBuilder = putRequestBuilder("/api/v1/ca/ca-identifier", requestJson);

      mockMvc.perform(requestBuilder)
          .andExpect(status().isBadRequest())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
          .andExpect(content().json(notFoundJson));
    });

    it("put without keys returns an error", () -> {
      String requestJson = "{\"type\":\"root\",\"root\":{}}";
      String notFoundJson = "{\"error\": \"All keys are required to set a CA. Please validate your input and retry your request.\"}";

      RequestBuilder requestBuilder = putRequestBuilder("/api/v1/ca/ca-identifier", requestJson);

      mockMvc.perform(requestBuilder)
          .andExpect(status().isBadRequest())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
          .andExpect(content().json(notFoundJson));
    });

    it("put with empty request returns an error", () -> {
      String requestJson = "{\"type\":\"root\"}";
      String notFoundJson = "{\"error\": \"All keys are required to set a CA. Please validate your input and retry your request.\"}";

      RequestBuilder requestBuilder = putRequestBuilder("/api/v1/ca/ca-identifier", requestJson);

      mockMvc.perform(requestBuilder)
          .andExpect(status().isBadRequest())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
          .andExpect(content().json(notFoundJson));
    });

    it("put cert with garbage returns an error", () -> {
      String requestJson = "{\"root\": }";

      RequestBuilder requestBuilder = putRequestBuilder("/api/v1/ca/ca-identifier", requestJson);

      mockMvc.perform(requestBuilder)
          .andExpect(status().isBadRequest());
    });
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
    return "\"updated_at\":\"" + frozenTime.format(ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")) + "\"";
  }

  private void freeze() {
    frozenTime = LocalDateTime.now(utc);
    currentTimeProvider.setOverrideTime(frozenTime);
  }
}