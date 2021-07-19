package org.cloudfoundry.credhub.integration;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.function.Consumer;

import static org.cloudfoundry.credhub.TestHelper.mockOutCurrentTimeProvider;
import static org.cloudfoundry.credhub.utils.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(profiles = { "unit-test", "minimum-duration" }, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredhubTestApp.class)
@Transactional
public class CertificateMinimumDurationTest {
    private static final String CREDENTIAL_NAME = "/credential/name";
    private static final Instant FROZEN_TIME = Instant.ofEpochSecond(1400011001L);

    @MockBean
    private CurrentTimeProvider mockCurrentTimeProvider;

    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Before
    public void beforeEach() {
        final Consumer<Long> fakeTimeSetter = mockOutCurrentTimeProvider(mockCurrentTimeProvider);

        fakeTimeSetter.accept(FROZEN_TIME.toEpochMilli());
        mockMvc = MockMvcBuilders
                .webAppContextSetup(webApplicationContext)
                .apply(springSecurity())
                .build();
    }

    @Test
    public void generatingCA_usesTheMinimumDuration() throws Exception {
        MockHttpServletRequestBuilder postRequest = post("/api/v1/data")
                .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                        "\"type\":\"certificate\"," +
                        "\"name\":\"" + CREDENTIAL_NAME + "\"," +
                        "\"parameters\":{" +
                        "\"common_name\":\"some-certificate\"," +
                        "\"is_ca\":true," +
                        "\"duration\":365" +
                        "}" +
                        "}");

        mockMvc.perform(postRequest).andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString();

        MockHttpServletRequestBuilder getRequest = get("/api/v1/certificates?name=" + CREDENTIAL_NAME)
                .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON);

        DocumentContext response = JsonPath.parse(mockMvc.perform(getRequest).andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString());
        Instant expiryDate = Instant.parse(response.read("$.certificates[0].versions[0].expiry_date").toString());
        assertThat(expiryDate, is(equalTo(mockCurrentTimeProvider.getInstant().plus(1825L, ChronoUnit.DAYS))));
    }

    @Test
    public void regeneratingALeafCertificate_usesTheMinimumDuration() throws Exception {
        MockHttpServletRequestBuilder postRequest = post("/api/v1/data")
                .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                        "\"type\":\"certificate\"," +
                        "\"name\":\"" + CREDENTIAL_NAME + "\"," +
                        "\"parameters\":{" +
                        "\"common_name\":\"some-certificate\"," +
                        "\"self_sign\":true," +
                        "\"duration\":365" +
                        "}" +
                        "}");

        mockMvc.perform(postRequest).andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString();

        MockHttpServletRequestBuilder getRequest = get("/api/v1/certificates?name=" + CREDENTIAL_NAME)
                .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON);

        DocumentContext response = JsonPath.parse(mockMvc.perform(getRequest).andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString());
        String certificateId = response.read("$.certificates[0].id").toString();


        postRequest = post("/api/v1/certificates/" + certificateId + "/regenerate")
                .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON);
        mockMvc.perform(postRequest).andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString();

        getRequest = get("/api/v1/certificates?name=" + CREDENTIAL_NAME)
                .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON);
        response = JsonPath.parse(mockMvc.perform(getRequest).andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString());

        Instant regeneratedExpiryDate = Instant.parse(response.read("$.certificates[0].versions[0].expiry_date").toString());
        List<Object> versions = response.read("$.certificates[0].versions[*]");

        assertThat(regeneratedExpiryDate, is(equalTo(mockCurrentTimeProvider.getInstant().plus(1460L, ChronoUnit.DAYS))));
        assertThat(versions.size(), is(equalTo(2)));
    }
}
