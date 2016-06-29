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

  private RequestBuilder getRequestBuilder(String path) {
    return get(path)
        .contentType(MediaType.APPLICATION_JSON_UTF8);
  }

  @Test
  public void canStoreNullsInCertificateAuthority() throws Exception {
    permutateTwoEmptiesTest(null);
  }

  @Test
  public void canStoreEmptyStringsAsNullsInCertificateAuthority() throws Exception {
    permutateTwoEmptiesTest("");
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

  private void permutateTwoEmptiesTest(String emptyValue) throws Exception {
    new PutCaSimulator(emptyValue, "my-priv")
        .setExpectation(200)
        .execute();

    new PutCaSimulator("my-pub", emptyValue)
        .setExpectation(200)
        .execute();
  }

  class PutCaSimulator {
    private final String pub;
    private final String priv;
    private int statusCode;
    private String badResponseJson;

    public PutCaSimulator(String pub, String priv) {
      this.pub = pub;
      this.priv = priv;
    }

    public void execute() throws Exception {
      CertificateAuthority certificateAuthorityForRequest = new CertificateAuthority(pub, priv);
      CertificateAuthority certificateAuthorityForResponse = new CertificateAuthority(
          transformEmptyToNull(pub),
          transformEmptyToNull(priv))
          .setUpdatedAt(frozenTime);

      String requestJson = json(certificateAuthorityForRequest);

      boolean isHttpOk = statusCode == 200;
      ResultMatcher expectedStatus = isHttpOk ? status().isOk() : status().isBadRequest();
      ResultActions result = mockMvc.perform(putRequestBuilder("/api/v1/ca/whatever", requestJson)).andExpect(expectedStatus);
      NamedAuthority certificateFromDb = caRepository.findOneByName("whatever");

      if (isHttpOk) {
        assertThat(certificateFromDb.generateView(), BeanMatchers.theSameAs(certificateAuthorityForResponse));
      } else {
        assertNull(certificateFromDb);
        result.andExpect(content().json(badResponseJson));
      }
    }

    private String transformEmptyToNull(String param) {
      return "".equals(param) ? null : param;
    }

    public PutCaSimulator setExpectation(int statusCode) {
      return setExpectation(statusCode, null);
    }

    public PutCaSimulator setExpectation(int statusCode, String badResponseJson) {
      this.statusCode = statusCode;
      this.badResponseJson = badResponseJson;
      return this;
    }
  }
}