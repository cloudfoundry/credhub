package org.cloudfoundry.credhub.auth

import org.cloudfoundry.credhub.CredhubTestApp
import org.cloudfoundry.credhub.utils.AuthConstants.Companion.EMPTY_ISSUER_JWT
import org.cloudfoundry.credhub.utils.AuthConstants.Companion.EXPIRED_TOKEN
import org.cloudfoundry.credhub.utils.AuthConstants.Companion.INVALID_ISSUER_JWT
import org.cloudfoundry.credhub.utils.AuthConstants.Companion.INVALID_SIGNATURE_JWT
import org.cloudfoundry.credhub.utils.AuthConstants.Companion.MALFORMED_TOKEN
import org.cloudfoundry.credhub.utils.AuthConstants.Companion.NULL_ISSUER_JWT
import org.cloudfoundry.credhub.utils.AuthConstants.Companion.VALID_ISSUER_JWT
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.core.IsEqual.equalTo
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mockito.`when`
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.SpyBean
import org.springframework.http.MediaType
import org.springframework.http.MediaType.APPLICATION_JSON
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.jwt.JwtValidators
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers
import org.springframework.security.web.FilterChainProxy
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.test.web.servlet.setup.StandaloneMockMvcBuilder
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RunWith(SpringRunner::class)
@ActiveProfiles(value = ["unit-test"], resolver = DatabaseProfileResolver::class)
@SpringBootTest(classes = [CredhubTestApp::class])
@Transactional
class OAuth2ExtraValidationFilterTest {
    @SpyBean
    private val oAuth2IssuerService: OAuth2IssuerService? = null

    private var mockMvc: MockMvc? = null
    private var spyController: SpyController? = null

    @Autowired
    private val springSecurityFilterChain: FilterChainProxy? = null

    @Autowired
    private var jwtDecoder: NimbusJwtDecoder? = null

    @Before
    @Throws(Exception::class)
    fun beforeEach() {
        spyController = SpyController()

        mockMvc =
            MockMvcBuilders
                .standaloneSetup(spyController!!)
                .apply<StandaloneMockMvcBuilder>(SecurityMockMvcConfigurers.springSecurity(springSecurityFilterChain!!))
                .build()
    }

    @Test
    @Throws(Exception::class)
    fun whenGivenValidIssuer_returns200() {
        // Replace jwtDecoder's JwtValidator with one created with the valid
        // issuer URI.
        jwtDecoder
            ?.setJwtValidator(
                JwtValidators.createDefaultWithIssuer(
                    "https://valid-uaa:8443/uaa/oauth/token",
                ),
            )

        this.mockMvc!!
            .perform(
                get("/api/v1/data")
                    .header("Authorization", "Bearer $VALID_ISSUER_JWT")
                    .accept(APPLICATION_JSON)
                    .contentType(APPLICATION_JSON),
            ).andExpect(status().isOk)
    }

    @Test
    @Throws(Exception::class)
    fun whenGivenInvalidIssuer_returns401() {
        val request =
            get("/api/v1/data?name=/picard")
                .header("Authorization", "Bearer $INVALID_ISSUER_JWT")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)

        this.mockMvc!!
            .perform(request)
            .andExpect(status().isUnauthorized)
            .andExpect(jsonPath("$.error").value(OAuth2ErrorCodes.INVALID_TOKEN))
    }

    @Test
    @Throws(Exception::class)
    fun whenGivenInvalidIssuer_onlyReturnsIntendedResponse() {
        val request =
            get("/api/v1/data?name=/picard")
                .header("Authorization", "Bearer $INVALID_ISSUER_JWT")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)

        val response =
            this.mockMvc!!
                .perform(request)
                .andExpect(status().isUnauthorized)
                .andExpect(jsonPath("$.error").value(OAuth2ErrorCodes.INVALID_TOKEN))
                .andReturn()
                .response
                .contentAsString
        assertThat(spyController!!.getDataCount, equalTo(0))
    }

    @Test
    @Throws(Exception::class)
    fun whenGivenMalformedToken_onlyReturnsIntendedResponse() {
        val request =
            get("/api/v1/data?name=/picard")
                .header("Authorization", "Bearer $MALFORMED_TOKEN")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)

        val response =
            this.mockMvc!!
                .perform(request)
                .andExpect(status().isUnauthorized)
                .andExpect(jsonPath("$.error").value(OAuth2ErrorCodes.INVALID_TOKEN))
                .andReturn()
                .response
                .contentAsString
        assertThat(spyController!!.getDataCount, equalTo(0))
    }

    @Test
    @Throws(Exception::class)
    fun whenGivenValidTokenDoesNotMatchJWTSignature_onlyReturnsIntendedResponse() {
        val request =
            get("/api/v1/data?name=/picard")
                .header("Authorization", "Bearer $INVALID_SIGNATURE_JWT")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)

        val response =
            this.mockMvc!!
                .perform(request)
                .andExpect(status().isUnauthorized)
                .andExpect(jsonPath("$.error").value(OAuth2ErrorCodes.INVALID_TOKEN))
                .andReturn()
                .response
                .contentAsString
        assertThat(spyController!!.getDataCount, equalTo(0))
    }

    @Test
    @Throws(Exception::class)
    fun whenGivenNullIssuer_returns401() {
        this.mockMvc!!
            .perform(
                get("/api/v1/data?name=/picard")
                    .header("Authorization", "Bearer $NULL_ISSUER_JWT")
                    .accept(APPLICATION_JSON)
                    .contentType(APPLICATION_JSON),
            ).andExpect(status().isUnauthorized)
            .andExpect(jsonPath("$.error").value(OAuth2ErrorCodes.INVALID_TOKEN))
    }

    @Test
    @Throws(Exception::class)
    fun whenEmptyIssuerSpecified_returns401() {
        this.mockMvc!!
            .perform(
                get("/api/v1/data?name=/picard")
                    .header("Authorization", "Bearer $EMPTY_ISSUER_JWT")
                    .accept(APPLICATION_JSON)
                    .contentType(APPLICATION_JSON),
            ).andExpect(status().isUnauthorized)
            .andExpect(jsonPath("$.error").value(OAuth2ErrorCodes.INVALID_TOKEN))
    }

    @Test
    @Throws(Exception::class)
    fun whenTokenIsHasExpired_returns401() {
        `when`<String>(oAuth2IssuerService!!.getIssuer()).thenReturn("https://valid-uaa:8443/uaa/oauth/token")
        this.mockMvc!!
            .perform(
                get("/api/v1/data?name=/sample-credential")
                    .header("Authorization", "Bearer $EXPIRED_TOKEN")
                    .accept(APPLICATION_JSON)
                    .contentType(APPLICATION_JSON),
            ).andExpect(status().isUnauthorized)
            .andExpect(jsonPath("$.error").value(CredHubJwtTimeValidator.ACCESS_TOKEN_EXPIRED))
    }

    @RestController
    inner class SpyController {
        var getDataCount: Int = 0

        val data: String
            @GetMapping(value = ["/api/v1/data"], produces = [MediaType.APPLICATION_JSON_UTF8_VALUE])
            get() {
                getDataCount += 1
                return "some data"
            }
    }
}
