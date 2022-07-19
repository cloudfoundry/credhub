package org.cloudfoundry.credhub.integration;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.function.Consumer;

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

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.repositories.CredentialRepository;
import org.cloudfoundry.credhub.repositories.CredentialVersionRepository;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;
import org.cloudfoundry.credhub.utils.BouncyCastleFipsConfigurer;
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

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
@ActiveProfiles(profiles = { "unit-test", "minimum-duration", }, resolver = DatabaseProfileResolver.class)
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

    @Autowired
    private CredentialVersionRepository credentialVersionRepository;

    @Autowired
    private CredentialRepository credentialRepository;

    @BeforeClass
    public static void beforeAll() {
        BouncyCastleFipsConfigurer.configure();
    }

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

        DocumentContext generateResponse = JsonPath.parse(mockMvc.perform(postRequest).andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString());

        assertThat(generateResponse.read("$.duration_overridden").toString(), is("true"));
        assertThat(generateResponse.read("$.duration_used"), is(1825));
        Instant expiryDate = Instant.parse(generateResponse.read("$.expiry_date").toString());
        assertThat(expiryDate, is(equalTo(mockCurrentTimeProvider.getInstant().plus(1825L, ChronoUnit.DAYS))));
    }

    @Test
    public void regeneratingALeafCertificateThatAlreadyHasMinimumDuration_doesNotHaveOverriddenFlagInResponse() throws Exception {
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

        DocumentContext generateResponse = JsonPath.parse(mockMvc.perform(postRequest).andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString());

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
        Configuration suppressExceptionConfiguration = Configuration
                .defaultConfiguration()
                .addOptions(Option.SUPPRESS_EXCEPTIONS);
        DocumentContext regenerateResponse = JsonPath.using(suppressExceptionConfiguration)
                .parse(mockMvc.perform(postRequest).andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString());

        Instant regeneratedExpiryDate = Instant.parse(regenerateResponse.read("$.expiry_date").toString());
        List<Object> versions = getVersionsForCertificate(CREDENTIAL_NAME);

        assertThat(generateResponse.read("$.duration_overridden"), is(true));
        assertThat(generateResponse.read("$.duration_used"), is(1460));
        assertThat(regeneratedExpiryDate, is(equalTo(mockCurrentTimeProvider.getInstant().plus(1460L, ChronoUnit.DAYS))));
        assertThat(versions.size(), is(equalTo(2)));
        assertThat(regenerateResponse.read("$.duration_overridden"), is(false));
        assertThat(regenerateResponse.read("$.duration_used"), is(1460));
    }

    @Test
    public void regeneratingAPreexistingLeafCertificateUsingCertificatesController_usesTheMinimumDuration() throws Exception {
        createExistingLeafCert(CREDENTIAL_NAME);

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


        MockHttpServletRequestBuilder postRequest = post("/api/v1/certificates/" + certificateId + "/regenerate")
                .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON);
        DocumentContext regenerateResponse = JsonPath.parse(mockMvc.perform(postRequest).andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString());

        List<Object> versions = getVersionsForCertificate(CREDENTIAL_NAME);

        Instant regeneratedExpiryDate = Instant.parse(regenerateResponse.read("$.expiry_date").toString());

        assertThat(regeneratedExpiryDate, is(equalTo(mockCurrentTimeProvider.getInstant().plus(1460L, ChronoUnit.DAYS))));
        assertThat(regenerateResponse.read("$.duration_overridden"), is(equalTo(true)));
        assertThat(regenerateResponse.read("$.duration_used"), is(equalTo(1460)));
        assertThat(versions.size(), is(equalTo(2)));
    }

    @Test
    public void regeneratingAPreexistingLeafCertificateUsingCredentialsController_usesTheMinimumDuration() throws Exception {
        createExistingLeafCert(CREDENTIAL_NAME);

        MockHttpServletRequestBuilder postRequest = post("/api/v1/data")
                .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                        "\"type\":\"certificate\"," +
                        "\"name\":\"" + CREDENTIAL_NAME + "\"," +
                        "\"regenerate\": true" +
                        "}");

        DocumentContext regenerateResponse = JsonPath.parse(mockMvc.perform(postRequest).andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString());

        Instant regeneratedExpiryDate = Instant.parse(regenerateResponse.read("$.expiry_date").toString());
        List<Object> versions = getVersionsForCertificate(CREDENTIAL_NAME);

        assertThat(regeneratedExpiryDate, is(equalTo(mockCurrentTimeProvider.getInstant().plus(1460L, ChronoUnit.DAYS))));
        assertThat(regenerateResponse.read("$.duration_overridden"), is(equalTo(true)));
        assertThat(regenerateResponse.read("$.duration_used"), is(equalTo(1460)));
        assertThat(versions.size(), is(equalTo(2)));
    }

    @Test
    public void regeneratingAPreexistingLeafCertificateUsingRegenerateController_usesTheMinimumDuration() throws Exception {
        createExistingLeafCert(CREDENTIAL_NAME);

        MockHttpServletRequestBuilder postRequest = post("/api/v1/regenerate")
                .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                        "\"name\":\"" + CREDENTIAL_NAME + "\"" +
                        "}");

        DocumentContext regenerateResponse = JsonPath.parse(mockMvc.perform(postRequest).andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString());

        Instant regeneratedExpiryDate = Instant.parse(regenerateResponse.read("$.expiry_date").toString());
        List<Object> versions = getVersionsForCertificate(CREDENTIAL_NAME);

        assertThat(regeneratedExpiryDate, is(equalTo(mockCurrentTimeProvider.getInstant().plus(1460L, ChronoUnit.DAYS))));
        assertThat(regenerateResponse.read("$.duration_overridden"), is(equalTo(true)));
        assertThat(regenerateResponse.read("$.duration_used"), is(equalTo(1460)));
        assertThat(versions.size(), is(equalTo(2)));
    }

    private List<Object> getVersionsForCertificate(String certificateName) throws Exception {
        MockHttpServletRequestBuilder getRequest = get("/api/v1/certificates?name=" + certificateName)
                .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON);
        DocumentContext response = JsonPath.parse(mockMvc.perform(getRequest).andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString());
        return response.read("$.certificates[0].versions[*]");
    }

    private void createExistingLeafCert(String certificateName) {
        // This pre-generated certificate has a duration of 1 year. The minimum duration profile sets a leaf-cert
        // minimum of 4 years.
        final String certificate = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDBjCCAe6gAwIBAgIULwWm7iTn7jAiCQ1BG65/vHaa5aQwDQYJKoZIhvcNAQEL\n" +
                "BQAwFDESMBAGA1UEAxMJdGVzdC1jZXJ0MB4XDTIxMDcyMjE5MzMwNVoXDTIyMDcy\n" +
                "MjE5MzMwNVowFDESMBAGA1UEAxMJdGVzdC1jZXJ0MIIBIjANBgkqhkiG9w0BAQEF\n" +
                "AAOCAQ8AMIIBCgKCAQEA1MMbM9dczQesiW7XTtKL5mjqe0O+R5A2+XvolgpzBqD7\n" +
                "uMugZKlav77qdXayHLEXYBhE2LA5Up1sP+e/9jGBPzx7Qnm1pXiqZpod+Bs9X/hH\n" +
                "33NIz60daaRePcXiRXm3MEQnqWk8PEclyGqOgzvsUpu8MxfaNwOdyIVy9zxBYmru\n" +
                "Q5SCUcbtXlDqb9leq5THeKbIYX143jtg9q7OpeXDY1gC70c0gVJVgrPRDyx8CFDM\n" +
                "YQRjsZMo94tVOFEvdM8XGg83lmtTl+UiinZOsNPWgYU4RUsF8dqT73y7eeL1Y0TQ\n" +
                "TVVft5D5hOACVBU8Gi6xjMcSul5NbFFJ+sivGTfygQIDAQABo1AwTjAdBgNVHQ4E\n" +
                "FgQUb1yc1vj4744wUxpeWoXyYdj9u9cwHwYDVR0jBBgwFoAUb1yc1vj4744wUxpe\n" +
                "WoXyYdj9u9cwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAiktin8Fk\n" +
                "UxM/K147TGIYkPRyzU43S8xskwH0xyqvIbT1IvVKja9CveaCxWH/zgaGhl5rGB8h\n" +
                "7Z69ZBxXhtcSWqqraD3wQVDiY6Ki8gLpbP0yFZyYA/GjXRjLTYJjXwfzDQ53SXJL\n" +
                "5/t4JtykZJpMwjQxixM0KjafpEqV074pyTUMfooFj6t4s0SBEFt6aQBZidwAVhem\n" +
                "FvmxFnOuO0ijG0+th8Pu/dYuvOxLEsLK+VfnDTGr+wDY1DMfetUiWTvv41dGezVu\n" +
                "L8VIfi4bpLByz/LeftYvOVi/6PgV3LT8Lz0VG63jro+1l+iRqtoTSU8Nx8Xd/BCQ\n" +
                "7iA5+5RleDWApg==\n" +
                "-----END CERTIFICATE-----\n";

        final Credential credential = new Credential(certificateName);
        credentialRepository.save(credential);

        final CertificateCredentialVersionData versionData = new CertificateCredentialVersionData(certificateName);
        versionData.setCertificateAuthority(false);
        versionData.setSelfSigned(true);
        versionData.setCertificate(certificate);
        versionData.setCredential(credential);
        credentialVersionRepository.save(versionData);
    }
}
