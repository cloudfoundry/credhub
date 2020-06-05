package org.cloudfoundry.credhub.auth

import java.security.Principal
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Date
import java.util.HashMap
import java.util.HashSet
import org.cloudfoundry.credhub.CredhubTestApp
import org.cloudfoundry.credhub.auth.UserContext.Companion.AUTH_METHOD_MUTUAL_TLS
import org.cloudfoundry.credhub.auth.UserContext.Companion.AUTH_METHOD_UAA
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.core.IsEqual.equalTo
import org.hamcrest.core.StringContains.containsString
import org.junit.Test
import org.junit.jupiter.api.Assertions
import org.junit.runner.RunWith
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock
import org.mockito.Mockito.spy
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.OAuth2Request
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.junit4.SpringRunner

@RunWith(SpringRunner::class)
@ActiveProfiles(profiles = ["unit-test"], resolver = DatabaseProfileResolver::class)
@SpringBootTest(classes = [CredhubTestApp::class])
class UserContextFactoryTest {
    @MockBean
    private val tokenServicesMock: ResourceServerTokenServices? = null

    @Autowired
    private val subject: UserContextFactory? = null

    @Test
    @Throws(Exception::class)
    fun fromAuthentication_readsFromOAuthDetails() {
        val oauth2Authentication = setupOAuthMock("TEST_GRANT_TYPE")
        val context = subject!!.createUserContext(oauth2Authentication)

        assertThat<String>(context.userId, equalTo("TEST_USER_ID"))
        assertThat<String>(context.userName, equalTo("TEST_USER_NAME"))
        assertThat<String>(context.issuer, equalTo("TEST_UAA_URL"))
        assertThat<String>(context.scope, equalTo("scope1,scope2"))
        assertThat<String>(context.grantType, equalTo("TEST_GRANT_TYPE"))
        assertThat(context.validFrom, equalTo(1413495264L))
        assertThat(context.validUntil, equalTo(1413538464L))
        assertThat<String>(context.authMethod, equalTo(AUTH_METHOD_UAA))
    }

    @Test
    @Throws(Exception::class)
    fun fromAuthentication_handlesSuppliedToken() {

        val oauth2Authentication = setupOAuthMock("TEST_GRANT_TYPE")

        val context = subject!!.createUserContext(oauth2Authentication, "tokenValue")

        assertThat<String>(context.userName, equalTo("TEST_USER_NAME"))
        assertThat<String>(context.issuer, containsString("TEST_UAA_URL"))
        assertThat<String>(context.scope, equalTo("scope1,scope2"))
        assertThat<String>(context.authMethod, equalTo(AUTH_METHOD_UAA))
    }

    @Test
    @Throws(Exception::class)
    fun fromAuthentication_handlesMtlsAuth() {

        val mtlsAuth = setupMtlsMock()
        val context = subject!!.createUserContext(mtlsAuth)

        assertThat<String>(context.userName, equalTo<String>(
            null))
        assertThat<String>(context.userId, equalTo<String>(null))
        assertThat<String>(context.issuer, equalTo<String>(null))
        assertThat<String>(context.scope, equalTo<String>(null))
        assertThat(context.validFrom, equalTo(1413495264L))
        assertThat(context.validUntil, equalTo(1413538464L))
        assertThat<String>(context.clientId, equalTo("CN=test_cn,OU=app:e054393e-c9c3-478b-9047-e6d05c307bf2"))
        assertThat<String>(context.authMethod, equalTo(AUTH_METHOD_MUTUAL_TLS))
    }

    @Test
    @Throws(Exception::class)
    fun getAclUser_fromOAuthPasswordGrant_returnsTheUserGuid() {
        val oauth2Authentication = setupOAuthMock("password")
        val context = subject!!.createUserContext(oauth2Authentication)

        assertThat<String>(context.actor,
            equalTo("uaa-user:TEST_USER_ID"))
    }

    @Test
    @Throws(Exception::class)
    fun getAclUser_fromOAuthClientGrant_returnsTheClientId() {
        val oauth2Authentication = setupOAuthMock("client_credentials")
        val context = subject!!.createUserContext(oauth2Authentication)

        assertThat<String>(context.actor,
            equalTo("uaa-client:TEST_CLIENT_ID"))
    }

    @Test
    @Throws(Exception::class)
    fun getAclUser_fromMtlsCertificate_returnsAppGuid() {
        val authenticationToken = setupMtlsMock()
        val context = subject!!.createUserContext(authenticationToken)

        assertThat<String>(context.actor,
            equalTo("mtls-app:e054393e-c9c3-478b-9047-e6d05c307bf2"))
    }

    @Test
    fun getAclUser_withInvalidGrantType_throwsException() {
        val oauth2Authentication = setupOAuthMock("client_credentials")
        val context = subject!!.createUserContext(oauth2Authentication)
        context.grantType = "bruce is crazy"

        Assertions.assertThrows(UserContext.UnsupportedGrantTypeException::class.java) {
            context.actor
        }
    }

    @Test
    fun getAclUser_withInvalidAuthMethod_throwsException() {
        val invalidAuthMethod = "not a valid auth method"
        val context = UserContext(
                "some-user-id",
                "some-user-name",
                "some-issuer",
                11223344,
                22334455,
                "some-client-id",
                "some-scope",
                "some-grant-type",
                invalidAuthMethod
        )

        Assertions.assertThrows(UserContext.UnsupportedAuthMethodException::class.java) {
            context.actor
        }
    }

    private fun setupOAuthMock(grantType: String): OAuth2Authentication {
        val authentication = mock(OAuth2Authentication::class.java)
        val oauth2Request = spy(OAuth2Request(
                null,
                "TEST_CLIENT_ID",
                null,
                false,
                null,
                null,
                null,
                null,
                null
        )
        )
        val token = mock(OAuth2AccessToken::class.java)
        val authDetails = mock(OAuth2AuthenticationDetails::class.java)

        val additionalInformation = HashMap<String, Any>()
        additionalInformation["user_id"] = "TEST_USER_ID"
        additionalInformation["user_name"] = "TEST_USER_NAME"
        additionalInformation["iss"] = "TEST_UAA_URL"
        additionalInformation["iat"] = 1413495264

        val scopes = HashSet<String>()
        scopes.add("scope1")
        scopes.add("scope2")

        `when`(oauth2Request.grantType).thenReturn(grantType)
        `when`(authentication.details).thenReturn(authDetails)
        `when`(authDetails.tokenValue).thenReturn("tokenValue")

        `when`(authentication.oAuth2Request).thenReturn(oauth2Request)
        `when`(token.additionalInformation).thenReturn(additionalInformation)
        `when`(token.expiration).thenReturn(Date.from(Instant.ofEpochSecond(1413538464)))
        `when`(token.scope).thenReturn(scopes)

        `when`(tokenServicesMock!!.readAccessToken("tokenValue")).thenReturn(token)

        return authentication
    }

    private fun setupMtlsMock(): PreAuthenticatedAuthenticationToken {
        val certificate = mock(X509Certificate::class.java)
        val principal = mock(Principal::class.java)
        val token = mock(PreAuthenticatedAuthenticationToken::class.java)

        `when`(certificate.subjectDN).thenReturn(principal)
        `when`(principal.name).thenReturn("CN=test_cn,OU=app:e054393e-c9c3-478b-9047-e6d05c307bf2")

        `when`(certificate.notAfter).thenReturn(Date.from(Instant.ofEpochSecond(1413538464L)))
        `when`(certificate.notBefore).thenReturn(Date.from(Instant.ofEpochSecond(1413495264L)))
        `when`(token.credentials).thenReturn(certificate)

        return token
    }
}
