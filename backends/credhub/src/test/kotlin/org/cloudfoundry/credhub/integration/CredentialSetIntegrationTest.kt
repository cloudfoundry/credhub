package org.cloudfoundry.credhub.integration

import org.apache.commons.lang3.StringUtils
import org.cloudfoundry.credhub.AuthConstants
import org.cloudfoundry.credhub.AuthConstants.ALL_PERMISSIONS_TOKEN
import org.cloudfoundry.credhub.CredhubTestApp
import org.cloudfoundry.credhub.DatabaseProfileResolver
import org.cloudfoundry.credhub.helpers.RequestHelper.generatePassword
import org.cloudfoundry.credhub.helpers.RequestHelper.setPassword
import org.hamcrest.CoreMatchers.`is`
import org.hamcrest.CoreMatchers.containsString
import org.hamcrest.CoreMatchers.equalTo
import org.hamcrest.MatcherAssert.assertThat
import org.json.JSONObject
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.skyscreamer.jsonassert.JSONAssert
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType.APPLICATION_JSON
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put
import org.springframework.test.web.servlet.result.MockMvcResultHandlers.print
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.DefaultMockMvcBuilder
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.context.WebApplicationContext

@RunWith(SpringRunner::class)
@ActiveProfiles(value = ["unit-test"], resolver = DatabaseProfileResolver::class)
@SpringBootTest(classes = [CredhubTestApp::class])
@Transactional
class CredentialSetIntegrationTest {

    @Autowired
    private lateinit var webApplicationContext: WebApplicationContext

    private lateinit var mockMvc: MockMvc

    companion object {
        private val CREDENTIAL_NAME = "/set_credential"
        private val CREDENTIAL_NAME_1024_CHARACTERS = StringUtils.rightPad(
            "/",
            1024,
            'a'
        )
    }

    @Before
    fun setUp() {
        mockMvc = MockMvcBuilders
            .webAppContextSetup(webApplicationContext)
            .apply<DefaultMockMvcBuilder>(springSecurity())
            .build()
    }

    @Test
    fun `rsa credential can be set without private key`() {
        val setRsaRequest = put("/api/v1/data")
            .header("Authorization", "Bearer ${AuthConstants.ALL_PERMISSIONS_TOKEN}")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            // language=JSON
            .content("""
                {
                    "name": "$CREDENTIAL_NAME",
                    "type": "rsa",
                    "value": {
                      "public_key": "a_certain_public_key",
                      "private_key": ""
                    }
                }
            """.trimIndent())

        this.mockMvc
            .perform(setRsaRequest)
            .andDo(print())
            .andExpect(status().isOk)
            .andReturn().response
            .contentAsString
    }

    @Test
    fun `user credential returns null username when set with blank string as username`() {
        val setUserRequest = put("/api/v1/data")
            .header("Authorization", "Bearer ${AuthConstants.ALL_PERMISSIONS_TOKEN}")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            // language=JSON
            .content("""
              {
                "name": "$CREDENTIAL_NAME",
                "type": "user",
                "value": {
                  "username": "",
                  "password": "some_silly_password"
                }
              }
            """.trimIndent())

        val response = this.mockMvc
            .perform(setUserRequest)
            .andDo(print())
            .andExpect(status().isOk)
            .andReturn().response
            .contentAsString

        assertThat(response, containsString("\"username\":null"))
    }

    @Test
    fun `credential should always be overwritten in set request`() {
        setPassword(
            mockMvc,
            CREDENTIAL_NAME,
            "original-password",
            ALL_PERMISSIONS_TOKEN
        )

        val secondResponse = setPassword(
            mockMvc,
            CREDENTIAL_NAME,
            "new-password",
            ALL_PERMISSIONS_TOKEN
        )
        val updatedPassword = JSONObject(secondResponse).getString("value")

        assertThat(updatedPassword, equalTo("new-password"))
    }

    @Test
    fun `credential names can have a length of 1024 characters`() {
        assertThat(CREDENTIAL_NAME_1024_CHARACTERS.length, `is`(equalTo(1024)))

        val setResponse = setPassword(
            mockMvc,
            CREDENTIAL_NAME_1024_CHARACTERS,
            "foobar",
            ALL_PERMISSIONS_TOKEN
        )
        val setPassword = JSONObject(setResponse).getString("value")

        assertThat(setPassword, equalTo("foobar"))

        val getResponse = generatePassword(
            mockMvc,
            CREDENTIAL_NAME_1024_CHARACTERS,
            true,
            14,
            ALL_PERMISSIONS_TOKEN
        )
        val getPassword = JSONObject(getResponse).getString("value")
        assertThat(getPassword.length, equalTo(14))
    }

    @Test
    fun `credential names that exceed the maximum length should result in 400`() {
        val name1025 = CREDENTIAL_NAME_1024_CHARACTERS + "a"
        assertThat(name1025.length, `is`(equalTo(1025)))

        setPassword(
            mockMvc,
            name1025,
            "foobar",
            ALL_PERMISSIONS_TOKEN
        )
        generatePassword(
            mockMvc,
            name1025,
            false,
            10,
            ALL_PERMISSIONS_TOKEN
        )
    }

    @Test
    fun `malformed private key should result in 400`() {

        val certificate = """
            -----BEGIN CERTIFICATE----- fake
            MIIDPjCCAiagAwIBAgIUIgg7xZVYF3qFsUVAhAFldTvCDJ4wDQYJKoZIhvcNAQEL
            BQAwFjEUMBIGA1UEAxMLZXhhbXBsZS5jb20wHhcNMTgwNjE1MTUwMDU3WhcNMTkw
            NjE1MTUwMDU3WjAWMRQwEgYDVQQDEwtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcN
            AQEBBQADggEPADCCAQoCggEBAM6z9Y/odS4pldElmK3syIbxhy5gPR5yvRIpEE89
            yXEkAJjyW8+zIjZM6/bIEIkAOAObXWLbcqI/Wv+FSxsUq55IYIZlaBpoHjl5rsvv
            inBbsKBChAPLuLBNNR8NJ/8gkZkeBsobBkkhTjZl1f6+GGAnLazqLxl8tyxwhNBe
            dlONwozUuJ1Vlve65L+cuapnKlmYz+ZYd4f75mJcs2OPUmXhbhTK+RI0gtZC84Qg
            0+pPheXjde/E8f0HrW2cO0wewxdAPnzD5MvQCZdc1ndpp2df4DZgLtxXozpLCSHF
            LxhnOkEGjtmxHG8YelrXZ0QbsZOumuvbWmK71PTalOKSe4cCAwEAAaOBgzCBgDAd
            BgNVHQ4EFgQUJbJRTUNhGiVXo/ELta+dlRCALwswUQYDVR0jBEowSIAUJbJRTUNh
            GiVXo/ELta+dlRCALwuhGqQYMBYxFDASBgNVBAMTC2V4YW1wbGUuY29tghQiCDvF
            lVgXeoWxRUCEAWV1O8IMnjAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IB
            AQAUM7zOD09vxMMGELbm3m+DgJOIhWm6zkibpzn1P1e7Pi7BOQ+2GvXBmn030yQU
            O5rKLNv49up9XGViKsPfVjbmxWp9WbElNPW+dJyO3zLMMkFtm/1T39Y+/A1LH3ww
            HSOnT3s54pSI66L9Mpiq+V2VmiOKEvoxy2mGQteMkXWSX31p0PlKMToV34TDIk9M
            9XyxHVWTf5NLe/gUEIoZatdvMmANKmKBiUWI5Aqnh93a2TXDu2Q8WXc0U0W8hsbD
            Wv7ec0Gguo4GtOomkmFIgXBLZd0ZqWywEjSGRy4us/71gBioTgCBMw8g75SzxX5u
            hQHS5//LiA50aEI4X0k5TDQp
            -----END CERTIFICATE-----
        """.trimIndent().replace("\n", "\\n")

        val invalidPrivateKey = """
            -----BEGIN RSA PRIVATE KEY----- fake
            MIIEpQIBAAKCAQEAwqIrV8HpCuPyuJ6VvyG7gVhYJGAOX4zhclxkTAKT5rkE4Lfj
            048GZsDghK+pHs+tVotfyrJzYGJoEBTn9Wy7kP5pQmLRF54imDztep15OlyoJmLZ
            fRgct/8Kyxkjgg3PKVw68IiNhnTlYaw4CAyZ/13mvw2cWIYlag9LV5R2ifcyubaY
            llxJhdWSXrcbYxrts1kRsUQTo99jJzKu71meLigMryaMry8xvjv1X8Yjq3s3Lud6
            gWZ6BuaaaVVIjI9clGgR1MkgKJgVkWjNzDRiCxYnq1LHCho9bgKgiY4p604zPk9M
            w4FhtCbOim6HOsHTimONZXfDNmfsJ9wJefA0UwIDAQABAoIBAEwsTcxFvuAdQFRS
            9IZePFUt7yklUtrAd0dbs4EwDRRiWu9b6NVWh4nVeMlVOlotq0hQucfJuXACc3m/
            xNx/lpTzjNyHcg/NOvrb9ZFkahqWQtTrIPVdZ3f3YBEGoKf4oZgtWX/j4Ye63j8w
            uKklzWttI66oNAVNUv1ESRdYql/p5/BVSJaVK4bdkXqYHX2j3PrPd30ICwxz0bGd
            41UdMiKMJhlkhIESsB8bcdRAEaMS2OaFKmBYIQF4RuY3syvFizJDtp/QEYfjy9tT
            Xokd3Wzs6dncn/yyfvT0+yCDjYsNAgFvBmfHNBorywxILdtgJHuc9oO2EOeg58VK
            Vt4eugECgYEA/wxb29pVamwxF71gKx/msBa5kwxV5N7NhTLdYyHwhQVErQlwn7Dg
            J8qLfZqmn231yoGpKLZsu2mxdRvpd9nvOiW+ZF+fsrS8SEs5dMEqhojALm8rur+Y
            5M0/Sk/A0lCbSmV+X7vmqaGzyNdgH7tYVIxXjAo4sEYN6GevjUB1JQECgYEAw1wZ
            BhhsIvW9gfbuCdiTGlezUuIO3oxjvSSTNUaGAB7GUqB26toBnXi6oQi5iGu/dCYU
            3CILOkV7kTX//2njOfWLp/kP+5nVKDgHoA/0gL609sgrdgkQ0KdZ3iuurimeqvDm
            U5hpPrNcwz7yPJ/M081ve84pHq3wzVKpi1dMNVMCgYEA4e5JxTTg63hR+MyqTylg
            SmanF2sa/7aa6r6HPRTIop1rG7m8Cco+lyEmdiq0JZDb5fr8JXOMWGylZa9HHwNw
            ltrukK3gowbVr1jr2dBv4mNrkvaqDzFAuJZU1XhWwDfliH7l9tpV17jFsUmQ/isQ
            cT0tJIG9e/Fiyphm+8K4wwECgYEAwXbCHUQwSoq7aiokX0HHo624G1tcyE2VNCk1
            UuwNJa9UTV01hqvwL4bwoyqluZCin55ayAk6vzEyBoLIiqLM8IfXDrhaeJpF+jdK
            bdt/EcRKJ53hVFnz+f3QxHDT4wu6YqSAI8bqarprIbuDXkAOMq3eOmfWVtiAgITc
            ++2uvZsCgYEAmpN2RfHxO3huEWFoE7LTy9WTv4DDHI+g8PeCUpP2pN/UmczInyQ4
            OlKeNTSxn9AkyYx9PJ8i1TIx6GyFIX4pkJczLEu+XINm82MKSBGuRL1EUvkVddx3
            6clZk5BLDXjmCtCr5DGZ01EbT0wsbsBM1GtoCS4+vUQkJVHb0r6/ZdXX=
            -----END RSA PRIVATE KEY-----
        """.trimIndent().replace("\n", "\\n")

        val request = put("/api/v1/data")
            .header("Authorization", "Bearer ${AuthConstants.ALL_PERMISSIONS_TOKEN}")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            // language=json
            .content(
                """
                  {
                    "name": "some-cert",
                    "type": "certificate",
                    "value": {
                      "ca": "$certificate",
                      "certificate": "$certificate",
                      "private_key": "$invalidPrivateKey"
                    }
                  }
                """.trimIndent()
            )

        val responseBody = this.mockMvc
            .perform(request)
            .andDo(print())
            .andExpect(status().isBadRequest)
            .andReturn().response
            .contentAsString

        JSONAssert.assertEquals(
            responseBody,
            """
                {
                  "error": "Private key is malformed. Keys must be PEM-encoded PKCS#1 or unencrypted PKCS#8 keys."
                }
            """.trimIndent(),
            true
        )
    }
}
