package org.cloudfoundry.credhub.integration;

import java.time.Instant;
import java.util.function.Consumer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;
import org.cloudfoundry.credhub.utils.BouncyCastleFipsConfigurer;
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.cloudfoundry.credhub.TestHelper.mockOutCurrentTimeProvider;
import static org.cloudfoundry.credhub.utils.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredhubTestApp.class)
@Transactional
public class GenerateModeTest {
    private static final String CREDENTIAL_NAME = "/credential/name";
    private static final Instant FROZEN_TIME = Instant.ofEpochSecond(1400011001L);

    @MockitoBean
    private CurrentTimeProvider mockCurrentTimeProvider;

    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext webApplicationContext;

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
    public void generatingACredential_inNoOverwriteMode_doesNotUpdateTheCredential() throws Exception {
        MockHttpServletRequestBuilder postRequest = post("/api/v1/data")
                .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                        "\"type\":\"password\"," +
                        "\"name\":\"" + CREDENTIAL_NAME + "\"" +
                        "}");

        DocumentContext response = JsonPath.parse(mockMvc.perform(postRequest).andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString());

        final String versionId = response.read("$.id").toString();

        postRequest = post("/api/v1/data")
                .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                        "\"type\":\"password\"," +
                        "\"name\":\"" + CREDENTIAL_NAME + "\"," +
                        "\"mode\": \"no-overwrite\"" +
                        "}");

        response = JsonPath.parse(mockMvc.perform(postRequest).andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString());

        assertThat(response.read("$.id").toString(), is(equalTo(versionId)));
    }

    @Test
    public void generatingACredential_inOverwriteMode_doesUpdateTheCredential() throws Exception {
        MockHttpServletRequestBuilder postRequest = post("/api/v1/data")
                .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                        "\"type\":\"password\"," +
                        "\"name\":\"" + CREDENTIAL_NAME + "\"," +
                        "\"parameters\":{" +
                        "\"length\":30" +
                        "}" +
                        "}");

        DocumentContext response = JsonPath.parse(mockMvc.perform(postRequest).andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString());

        final String firstVersionId = response.read("$.id").toString();

        postRequest = post("/api/v1/data")
                .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                        "\"type\":\"password\"," +
                        "\"name\":\"" + CREDENTIAL_NAME + "\"," +
                        "\"mode\": \"overwrite\"," +
                        "\"parameters\":{" +
                        "\"length\":30" +
                        "}" +
                        "}");

        response = JsonPath.parse(mockMvc.perform(postRequest).andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString());

        final String secondVersionId = response.read("$.id").toString();

        assertThat(secondVersionId, is(not(equalTo(firstVersionId))));
    }

    @Test
    public void generatingACredential_whenInvalidModeIsSet_returns400() throws Exception {
        final MockHttpServletRequestBuilder postRequest = post("/api/v1/data")
                .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                        "\"type\":\"password\"," +
                        "\"name\":\"" + CREDENTIAL_NAME + "\"," +
                        "\"mode\": \"invalid\"" +
                        "}");

        final String expectedError = "The request could not be fulfilled because the request path or body did not meet expectation. Please check the documentation for required formatting and retry your request.";

        mockMvc.perform(postRequest)
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(jsonPath("$.error").value(expectedError));
    }

    @Test
    public void generatingACredential_whenNoOverwriteIsSet_andTheCredentialDoesNotExist_createsTheCredential() throws Exception {
        final MockHttpServletRequestBuilder postRequest = post("/api/v1/data")
                .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                        "\"type\":\"password\"," +
                        "\"name\":\"" + CREDENTIAL_NAME + "\"," +
                        "\"mode\": \"no-overwrite\"," +
                        "\"parameters\":{" +
                        "\"length\":30" +
                        "}" +
                        "}");

        final DocumentContext response = JsonPath.parse(mockMvc.perform(postRequest).andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString());

        final String versionId = response.read("$.id").toString();
        assertThat(versionId, is(notNullValue()));
    }

    @Test
    public void generatingACredential_whenConvergeIsSet_andTheCredentialDoesNotExist_createsTheCredential() throws Exception {
        final MockHttpServletRequestBuilder postRequest = post("/api/v1/data")
                .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                        "\"type\":\"password\"," +
                        "\"name\":\"" + CREDENTIAL_NAME + "\"," +
                        "\"mode\": \"converge\"," +
                        "\"parameters\":{" +
                        "\"length\":30" +
                        "}" +
                        "}");

        final DocumentContext response = JsonPath.parse(mockMvc.perform(postRequest).andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString());

        final String versionId = response.read("$.id").toString();
        assertThat(versionId, is(notNullValue()));
    }

    @Test
    public void generatingACredential_whenConvergeIsSet_andTheCredentialParamsAreDifferentFromTheExistingCredential_updatesTheCredential() throws Exception {
        MockHttpServletRequestBuilder postRequest = post("/api/v1/data")
                .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                        "\"type\":\"password\"," +
                        "\"name\":\"" + CREDENTIAL_NAME + "\"," +
                        "\"parameters\":{" +
                        "\"length\":30" +
                        "}" +
                        "}");

        DocumentContext response = JsonPath.parse(mockMvc.perform(postRequest).andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString());

        final String firstVersionId = response.read("$.id").toString();

        postRequest = post("/api/v1/data")
                .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                        "\"type\":\"password\"," +
                        "\"name\":\"" + CREDENTIAL_NAME + "\"," +
                        "\"mode\": \"converge\"," +
                        "\"parameters\":{" +
                        "\"length\":31" +
                        "}" +
                        "}");

        response = JsonPath.parse(mockMvc.perform(postRequest).andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString());

        final String secondVersionId = response.read("$.id").toString();

        assertThat(secondVersionId, is(not(equalTo(firstVersionId))));
    }

    @Test
    public void generatingACredential_whenConvergeIsSet_andTheCredentialParamsAreTheSameAsTheExistingCredential_doesNotUpdatesTheCredential() throws Exception {
        MockHttpServletRequestBuilder postRequest = post("/api/v1/data")
                .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                        "\"type\":\"password\"," +
                        "\"name\":\"" + CREDENTIAL_NAME + "\"," +
                        "\"parameters\":{" +
                        "\"length\":30" +
                        "}" +
                        "}");

        DocumentContext response = JsonPath.parse(mockMvc.perform(postRequest).andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString());

        final String firstVersionId = response.read("$.id").toString();

        postRequest = post("/api/v1/data")
                .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                        "\"type\":\"password\"," +
                        "\"name\":\"" + CREDENTIAL_NAME + "\"," +
                        "\"mode\": \"converge\"," +
                        "\"parameters\":{" +
                        "\"length\":30" +
                        "}" +
                        "}");

        response = JsonPath.parse(mockMvc.perform(postRequest).andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString());

        final String secondVersionId = response.read("$.id").toString();

        assertThat(secondVersionId, is(equalTo(firstVersionId)));
    }

    @Test
    public void generatingACredential_whenBothModeAndOverwriteAreSet_returnsA400() throws Exception {
        final MockHttpServletRequestBuilder postRequest = post("/api/v1/data")
                .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                        "\"type\":\"password\"," +
                        "\"name\":\"" + CREDENTIAL_NAME + "\"," +
                        "\"overwrite\": false," +
                        "\"mode\": \"converge\"" +
                        "}");

        final String expectedError = "The parameters overwrite and mode cannot be combined. Please update and retry your request.";

        mockMvc.perform(postRequest)
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(jsonPath("$.error").value(expectedError));
    }

    @Test
    public void generatingACredential_whenConvergeIsSet_andTheCertificateParamsAreTheSameAsTheExistingCredentialExceptDuration_doesNotUpdatesTheCredential() throws Exception {
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

        DocumentContext response = JsonPath.parse(mockMvc.perform(postRequest).andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString());

        final String firstVersionId = response.read("$.id").toString();

        postRequest = post("/api/v1/data")
                .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                        "\"type\":\"certificate\"," +
                        "\"name\":\"" + CREDENTIAL_NAME + "\"," +
                        "\"parameters\":{" +
                        "\"common_name\":\"some-certificate\"," +
                        "\"is_ca\":true," +
                        "\"duration\":730" +
                        "}" +
                        "}");

        response = JsonPath.parse(mockMvc.perform(postRequest).andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString());

        final String secondVersionId = response.read("$.id").toString();

        assertThat(secondVersionId, is(equalTo(firstVersionId)));
    }

    @Test
    public void generatingACredential_whenModeIsSetAsParameter_returnsA400() throws Exception {
        final MockHttpServletRequestBuilder postRequest = post("/api/v1/data")
                .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                        "\"type\":\"password\"," +
                        "\"name\":\"" + CREDENTIAL_NAME + "\"," +
                        "\"parameters\":{" +
                        "\"length\":30," +
                        "\"mode\": \"converge\"" +
                        "}" +
                        "}");

        final String expectedError = "The request includes an unrecognized parameter 'mode'. Please update or remove this parameter and retry your request.";

        mockMvc.perform(postRequest).andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(jsonPath("$.error").value(expectedError));
    }
}
