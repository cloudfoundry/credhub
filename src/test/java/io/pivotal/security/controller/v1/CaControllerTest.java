package io.pivotal.security.controller.v1;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.MockitoSpringTest;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.repository.InMemorySecretRepository;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.view.RootCertificateSecret;
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
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.ConfigurableWebApplicationContext;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
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
  private InMemorySecretRepository caSecretRepository;

  @InjectMocks
  @Autowired
  private CaController caController;

  @Autowired @Qualifier("currentTimeProvider")
  CurrentTimeProvider currentTimeProvider;

  private MockMvc mockMvc;

  @Before
  public void setUp() {
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

    RootCertificateSecret expected = new RootCertificateSecret("public_key", "private_key");
    NamedCertificateSecret saved = (NamedCertificateSecret)caSecretRepository.findOneByName("ca-identifier");
    Assert.assertThat(new RootCertificateSecret(saved.getPub(), saved.getPriv()), BeanMatchers.theSameAs(expected));
  }

  private RequestBuilder putRequestBuilder(String path, String requestBody) {
    return put(path)
        .content(requestBody)
        .contentType(MediaType.APPLICATION_JSON_UTF8);
  }

}