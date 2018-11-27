package org.cloudfoundry.credhub.integration;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.util.AuthConstants;
import org.cloudfoundry.credhub.util.CertificateStringConstants;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.cloudfoundry.credhub.util.TestConstants;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.skyscreamer.jsonassert.JSONAssert;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import static org.cloudfoundry.credhub.helper.RequestHelper.generatePassword;
import static org.cloudfoundry.credhub.helper.RequestHelper.setPassword;
import static org.cloudfoundry.credhub.util.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.cloudfoundry.credhub.util.TestConstants.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class CredentialSetTest {
  private static final String CREDENTIAL_NAME = "/set_credential";
  private static final String CREDENTIAL_NAME_1024_CHARACTERS = StringUtils.rightPad("/", 1024, 'a');

  @Autowired
  private WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;
  private Object caCertificate;

  @Before
  public void setUp() {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();
  }

  @Test
  public void rsaCredentialCanBeSetWithoutPrivateKey() throws Exception {
    MockHttpServletRequestBuilder setRsaRequest = put("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\n"
            + "  \"name\" :\"" + CREDENTIAL_NAME + "\",\n"
            + "  \"type\" : \"rsa\",\n"
            + "  \"value\" : {\n"
            + "    \"public_key\" : \"a_certain_public_key\",\n"
            + "    \"private_key\" : \"\"\n"
            + "  }\n"
            + "}");

    this.mockMvc
        .perform(setRsaRequest)
        .andDo(print())
        .andExpect(status().isOk())
        .andReturn().getResponse()
        .getContentAsString();

  }

  @Test
  public void userCredentialReturnsNullUsernameWhenSetWithBlankStringAsUsername() throws Exception {
    MockHttpServletRequestBuilder setUserRequest = put("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        //language=JSON
        .content("{\n"
            + "  \"name\" :\"" + CREDENTIAL_NAME + "\",\n"
            + "  \"type\" : \"user\",\n"
            + "  \"value\" : {\n"
            + "    \"username\" : \"\",\n"
            + "    \"password\" : \"some_silly_password\"\n"
            + "  }\n"
            + "}");

    String response = this.mockMvc
        .perform(setUserRequest)
        .andDo(print())
        .andExpect(status().isOk())
        .andReturn().getResponse()
        .getContentAsString();

    assertThat(response, containsString("\"username\":null"));
  }

  @Test
  public void credentialShouldAlwaysBeOverwrittenInSetRequest() throws Exception {
    setPassword(mockMvc, CREDENTIAL_NAME, "original-password", ALL_PERMISSIONS_TOKEN);

    String secondResponse = setPassword(mockMvc, CREDENTIAL_NAME, "new-password", ALL_PERMISSIONS_TOKEN);
    String updatedPassword = (new JSONObject(secondResponse)).getString("value");

    assertThat(updatedPassword, equalTo("new-password"));
  }

  @Test
  public void credentialNamesCanHaveALengthOf1024Characters() throws Exception {
    assertThat(CREDENTIAL_NAME_1024_CHARACTERS.length(), is(equalTo(1024)));

    String setResponse = setPassword(mockMvc, CREDENTIAL_NAME_1024_CHARACTERS, "foobar", ALL_PERMISSIONS_TOKEN);
    String setPassword = (new JSONObject(setResponse)).getString("value");

    assertThat(setPassword, equalTo("foobar"));

    String getResponse = generatePassword(mockMvc, CREDENTIAL_NAME_1024_CHARACTERS, true, 14, ALL_PERMISSIONS_TOKEN);
    String getPassword = (new JSONObject(getResponse)).getString("value");
    assertThat(getPassword.length(), equalTo(14));
  }

  @Test
  public void credentialNamesThatExceedTheMaximumLengthShouldResultInA400() throws Exception{
    String name1025 = CREDENTIAL_NAME_1024_CHARACTERS + "a";
    assertThat(name1025.length(), is(equalTo(1025)));

    setPassword(mockMvc, name1025, "foobar", ALL_PERMISSIONS_TOKEN);
    generatePassword(mockMvc, name1025, false, 10, ALL_PERMISSIONS_TOKEN);
  }

  @Test
  public void malformedPrivateKeyShouldResultInA400() throws Exception {

    final String certificate =
        "-----BEGIN CERTIFICATE-----fake\\n"
            + "MIIDPjCCAiagAwIBAgIUIgg7xZVYF3qFsUVAhAFldTvCDJ4wDQYJKoZIhvcNAQEL\\n"
            + "BQAwFjEUMBIGA1UEAxMLZXhhbXBsZS5jb20wHhcNMTgwNjE1MTUwMDU3WhcNMTkw\\n"
            + "NjE1MTUwMDU3WjAWMRQwEgYDVQQDEwtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcN\\n"
            + "AQEBBQADggEPADCCAQoCggEBAM6z9Y/odS4pldElmK3syIbxhy5gPR5yvRIpEE89\\n"
            + "yXEkAJjyW8+zIjZM6/bIEIkAOAObXWLbcqI/Wv+FSxsUq55IYIZlaBpoHjl5rsvv\\n"
            + "inBbsKBChAPLuLBNNR8NJ/8gkZkeBsobBkkhTjZl1f6+GGAnLazqLxl8tyxwhNBe\\n"
            + "dlONwozUuJ1Vlve65L+cuapnKlmYz+ZYd4f75mJcs2OPUmXhbhTK+RI0gtZC84Qg\\n"
            + "0+pPheXjde/E8f0HrW2cO0wewxdAPnzD5MvQCZdc1ndpp2df4DZgLtxXozpLCSHF\\n"
            + "LxhnOkEGjtmxHG8YelrXZ0QbsZOumuvbWmK71PTalOKSe4cCAwEAAaOBgzCBgDAd\\n"
            + "BgNVHQ4EFgQUJbJRTUNhGiVXo/ELta+dlRCALwswUQYDVR0jBEowSIAUJbJRTUNh\\n"
            + "GiVXo/ELta+dlRCALwuhGqQYMBYxFDASBgNVBAMTC2V4YW1wbGUuY29tghQiCDvF\\n"
            + "lVgXeoWxRUCEAWV1O8IMnjAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IB\\n"
            + "AQAUM7zOD09vxMMGELbm3m+DgJOIhWm6zkibpzn1P1e7Pi7BOQ+2GvXBmn030yQU\\n"
            + "O5rKLNv49up9XGViKsPfVjbmxWp9WbElNPW+dJyO3zLMMkFtm/1T39Y+/A1LH3ww\\n"
            + "HSOnT3s54pSI66L9Mpiq+V2VmiOKEvoxy2mGQteMkXWSX31p0PlKMToV34TDIk9M\\n"
            + "9XyxHVWTf5NLe/gUEIoZatdvMmANKmKBiUWI5Aqnh93a2TXDu2Q8WXc0U0W8hsbD\\n"
            + "Wv7ec0Gguo4GtOomkmFIgXBLZd0ZqWywEjSGRy4us/71gBioTgCBMw8g75SzxX5u\\n"
            + "hQHS5//LiA50aEI4X0k5TDQp\\n"
            + "-----END CERTIFICATE-----";

    final String invalidPrivateKey = "-----BEGIN RSA PRIVATE KEY-----fake\\n"
        + "MIIEpQIBAAKCAQEAwqIrV8HpCuPyuJ6VvyG7gVhYJGAOX4zhclxkTAKT5rkE4Lfj\\n"
        + "048GZsDghK+pHs+tVotfyrJzYGJoEBTn9Wy7kP5pQmLRF54imDztep15OlyoJmLZ\\n"
        + "fRgct/8Kyxkjgg3PKVw68IiNhnTlYaw4CAyZ/13mvw2cWIYlag9LV5R2ifcyubaY\\n"
        + "llxJhdWSXrcbYxrts1kRsUQTo99jJzKu71meLigMryaMry8xvjv1X8Yjq3s3Lud6\\n"
        + "gWZ6BuaaaVVIjI9clGgR1MkgKJgVkWjNzDRiCxYnq1LHCho9bgKgiY4p604zPk9M\\n"
        + "w4FhtCbOim6HOsHTimONZXfDNmfsJ9wJefA0UwIDAQABAoIBAEwsTcxFvuAdQFRS\\n"
        + "9IZePFUt7yklUtrAd0dbs4EwDRRiWu9b6NVWh4nVeMlVOlotq0hQucfJuXACc3m/\\n"
        + "xNx/lpTzjNyHcg/NOvrb9ZFkahqWQtTrIPVdZ3f3YBEGoKf4oZgtWX/j4Ye63j8w\\n"
        + "uKklzWttI66oNAVNUv1ESRdYql/p5/BVSJaVK4bdkXqYHX2j3PrPd30ICwxz0bGd\\n"
        + "41UdMiKMJhlkhIESsB8bcdRAEaMS2OaFKmBYIQF4RuY3syvFizJDtp/QEYfjy9tT\\n"
        + "Xokd3Wzs6dncn/yyfvT0+yCDjYsNAgFvBmfHNBorywxILdtgJHuc9oO2EOeg58VK\\n"
        + "Vt4eugECgYEA/wxb29pVamwxF71gKx/msBa5kwxV5N7NhTLdYyHwhQVErQlwn7Dg\\n"
        + "J8qLfZqmn231yoGpKLZsu2mxdRvpd9nvOiW+ZF+fsrS8SEs5dMEqhojALm8rur+Y\\n"
        + "5M0/Sk/A0lCbSmV+X7vmqaGzyNdgH7tYVIxXjAo4sEYN6GevjUB1JQECgYEAw1wZ\\n"
        + "BhhsIvW9gfbuCdiTGlezUuIO3oxjvSSTNUaGAB7GUqB26toBnXi6oQi5iGu/dCYU\\n"
        + "3CILOkV7kTX//2njOfWLp/kP+5nVKDgHoA/0gL609sgrdgkQ0KdZ3iuurimeqvDm\\n"
        + "U5hpPrNcwz7yPJ/M081ve84pHq3wzVKpi1dMNVMCgYEA4e5JxTTg63hR+MyqTylg\\n"
        + "SmanF2sa/7aa6r6HPRTIop1rG7m8Cco+lyEmdiq0JZDb5fr8JXOMWGylZa9HHwNw\\n"
        + "ltrukK3gowbVr1jr2dBv4mNrkvaqDzFAuJZU1XhWwDfliH7l9tpV17jFsUmQ/isQ\\n"
        + "cT0tJIG9e/Fiyphm+8K4wwECgYEAwXbCHUQwSoq7aiokX0HHo624G1tcyE2VNCk1\\n"
        + "UuwNJa9UTV01hqvwL4bwoyqluZCin55ayAk6vzEyBoLIiqLM8IfXDrhaeJpF+jdK\\n"
        + "bdt/EcRKJ53hVFnz+f3QxHDT4wu6YqSAI8bqarprIbuDXkAOMq3eOmfWVtiAgITc\\n"
        + "++2uvZsCgYEAmpN2RfHxO3huEWFoE7LTy9WTv4DDHI+g8PeCUpP2pN/UmczInyQ4\\n"
        + "OlKeNTSxn9AkyYx9PJ8i1TIx6GyFIX4pkJczLEu+XINm82MKSBGuRL1EUvkVddx3\\n"
        + "6clZk5BLDXjmCtCr5DGZ01EbT0wsbsBM1GtoCS4+vUQkJVHb0r6/ZdXX=\\n"
        + "-----END RSA PRIVATE KEY-----";


    MockHttpServletRequestBuilder request = put("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(
            "{"
            + "\"name\":\"some-cert\","
            + "\"type\":\"certificate\","
            + "\"value\":{"
            + "\"ca\": \"" + certificate + "\","
            + "\"certificate\":\"" + certificate + "\","
            + "\"private_key\":\"" + invalidPrivateKey + "\""
            + "}"
            + "}"
        );

    String responseBody = this.mockMvc
        .perform(request)
        .andDo(print())
        .andExpect(status().isBadRequest())
        .andReturn().getResponse()
        .getContentAsString();

    JSONAssert.assertEquals(responseBody, "{\"error\":\"Private key is malformed.\"}", true);
  }
}
