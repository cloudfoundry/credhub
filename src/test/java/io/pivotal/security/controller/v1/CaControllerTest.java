package io.pivotal.security.controller.v1;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.MockitoSpringTest;
import io.pivotal.security.entity.NamedAuthority;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.repository.InMemoryAuthorityRepository;
import io.pivotal.security.repository.InMemorySecretRepository;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.view.CertificateAuthority;
import org.exparity.hamcrest.BeanMatchers;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.ConfigurableWebApplicationContext;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneId;

import static junit.framework.TestCase.assertNull;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Transactional
@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@WebAppConfiguration
public class CaControllerTest extends MockitoSpringTest {

  @Autowired
  protected ConfigurableWebApplicationContext context;

  @Autowired
  private ObjectMapper objectMapper;

  @Autowired
  private InMemorySecretRepository secretRepository;

  @Autowired
  private InMemoryAuthorityRepository caRepository;

  @InjectMocks
  @Autowired
  private CaController caController;

  @Autowired @Qualifier("currentTimeProvider")
  CurrentTimeProvider currentTimeProvider;

  private MockMvc mockMvc;

  private final ZoneId utc = ZoneId.of("UTC");
  private LocalDateTime frozenTime;

  @Before
  public void setUp() {
    freeze();
    mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
  }

  @After
  public void tearDown() {
    currentTimeProvider.reset();
  }

  @Test
  public void validPutRootCa() throws Exception {
    String requestJson = "{\"root\":{\"public\":\"public_key\",\"private\":\"private_key\"}}";

    RequestBuilder requestBuilder = putRequestBuilder("/api/v1/ca/ca-identifier", requestJson);

    mockMvc.perform(requestBuilder)
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(requestJson));

    CertificateAuthority expected = new CertificateAuthority("public_key", "private_key");
    NamedCertificateAuthority saved = (NamedCertificateAuthority) caRepository.findOneByName("ca-identifier");
    Assert.assertThat(new CertificateAuthority(saved.getPub(), saved.getPriv()), BeanMatchers.theSameAs(expected));
    Assert.assertNull(secretRepository.findOneByName("ca-identifier"));
  }

  @Test
  public void validGetReturnsCertificateAuthority() throws Exception {
    String requestJson = "{\"root\":{\"public\":\"my_public_key\",\"private\":\"my_private_key\"}}";
    NamedCertificateAuthority namedCertificateAuthority = new NamedCertificateAuthority("my_name");
    namedCertificateAuthority.setPub("my_public_key");
    namedCertificateAuthority.setPriv("my_private_key");
    caRepository.save(namedCertificateAuthority);

    RequestBuilder requestBuilder = getRequestBuilder("/api/v1/ca/my_name");
    mockMvc.perform(requestBuilder)
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(requestJson));
  }

  public void validPutCertificateAuthority_twice() throws Exception {
    String requestJson = "{\"root\":{\"public\":\"pub\",\"private\":\"priv\"}}";
    String requestJson2 = "{\"root\":{\"public\":\"pub 2\",\"private\":\"priv 2\"}}";

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

    CertificateAuthority expected = new CertificateAuthority("pub 2", "priv 2");
    NamedCertificateAuthority saved = (NamedCertificateAuthority) caRepository.findOneByName("ca-identifier");
    Assert.assertThat(new CertificateAuthority(saved.getPub(), saved.getPriv()), BeanMatchers.theSameAs(expected));
  }

  @Test
  public void getCertificateAuthority_whenNotFound_returns404() throws Exception {
    String notFoundJson = "{\"error\": \"CA not found. Please validate your input and retry your request.\"}";

    RequestBuilder requestBuilder = getRequestBuilder("/api/v1/ca/my_name");

    mockMvc.perform(requestBuilder)
        .andExpect(status().isNotFound())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(notFoundJson));
  }

  @Test
  public void putCert_withOnlyPublic_returnsError() throws Exception {
    String requestJson = "{\"root\":{\"public\":\"my_public_key\"}}";
    String notFoundJson = "{\"error\": \"All keys are required to set a CA. Please validate your input and retry your request.\"}";

    RequestBuilder requestBuilder = putRequestBuilder("/api/v1/ca/ca-identifier", requestJson);

    mockMvc.perform(requestBuilder)
        .andExpect(status().isBadRequest())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(notFoundJson));
  }

  @Test
  public void putCert_withOnlyPrivate_returnsError() throws Exception {
    String requestJson = "{\"root\":{\"private\":\"my_private_key\"}}";
    String notFoundJson = "{\"error\": \"All keys are required to set a CA. Please validate your input and retry your request.\"}";

    RequestBuilder requestBuilder = putRequestBuilder("/api/v1/ca/ca-identifier", requestJson);

    mockMvc.perform(requestBuilder)
        .andExpect(status().isBadRequest())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(notFoundJson));
  }

  @Test
  public void putCert_withoutKeys_returnsError() throws Exception {
    String requestJson = "{\"root\":{}}";
    String notFoundJson = "{\"error\": \"All keys are required to set a CA. Please validate your input and retry your request.\"}";

    RequestBuilder requestBuilder = putRequestBuilder("/api/v1/ca/ca-identifier", requestJson);

    mockMvc.perform(requestBuilder)
        .andExpect(status().isBadRequest())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(notFoundJson));
  }

  @Test
  public void putCert_withEmptyRequest_returnsError() throws Exception {
    String requestJson = "{}";
    String notFoundJson = "{\"error\": \"All keys are required to set a CA. Please validate your input and retry your request.\"}";

    RequestBuilder requestBuilder = putRequestBuilder("/api/v1/ca/ca-identifier", requestJson);

    mockMvc.perform(requestBuilder)
        .andExpect(status().isBadRequest())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(notFoundJson));
  }

  @Test
  public void putCert_withGarbageRequest_returnsError() throws Exception {
    String requestJson = "{\"root\": }";

    RequestBuilder requestBuilder = putRequestBuilder("/api/v1/ca/ca-identifier", requestJson);

    mockMvc.perform(requestBuilder)
        .andExpect(status().isBadRequest());
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

  private String json(Object o) throws IOException {
    return objectMapper.writeValueAsString(o);
  }

  private void freeze() {
    frozenTime = LocalDateTime.now(utc);
    currentTimeProvider.setOverrideTime(frozenTime);
  }
}