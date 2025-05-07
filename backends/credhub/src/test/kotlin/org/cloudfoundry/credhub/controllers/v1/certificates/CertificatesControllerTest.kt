package org.cloudfoundry.credhub.controllers.v1.certificates

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.assertj.core.api.Assertions.assertThat
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.certificates.CertificatesController
import org.cloudfoundry.credhub.constants.CredentialType
import org.cloudfoundry.credhub.credential.CertificateCredentialValue
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion
import org.cloudfoundry.credhub.helpers.CredHubRestDocs
import org.cloudfoundry.credhub.helpers.JsonHelpers
import org.cloudfoundry.credhub.helpers.MockMvcFactory
import org.cloudfoundry.credhub.helpers.credHubAuthHeader
import org.cloudfoundry.credhub.requests.CertificateRegenerateRequest
import org.cloudfoundry.credhub.requests.UpdateTransitionalVersionRequest
import org.cloudfoundry.credhub.utils.BouncyCastleFipsConfigurer
import org.cloudfoundry.credhub.utils.TestConstants
import org.cloudfoundry.credhub.views.CertificateCredentialView
import org.cloudfoundry.credhub.views.CertificateCredentialsView
import org.cloudfoundry.credhub.views.CertificateGenerationView
import org.cloudfoundry.credhub.views.CertificateVersionView
import org.cloudfoundry.credhub.views.CertificateView
import org.cloudfoundry.credhub.views.CredentialView
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Rule
import org.junit.Test
import org.skyscreamer.jsonassert.JSONAssert
import org.springframework.http.MediaType
import org.springframework.restdocs.JUnitRestDocumentation
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.delete
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.put
import org.springframework.restdocs.payload.JsonFieldType
import org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath
import org.springframework.restdocs.payload.PayloadDocumentation.requestFields
import org.springframework.restdocs.request.ParameterDescriptor
import org.springframework.restdocs.request.RequestDocumentation.parameterWithName
import org.springframework.restdocs.request.RequestDocumentation.pathParameters
import org.springframework.restdocs.request.RequestDocumentation.queryParameters
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.security.Security
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID

class CertificatesControllerTest {
    @Rule
    @JvmField
    val restDocumentation = JUnitRestDocumentation()

    lateinit var mockMvc: MockMvc
    private lateinit var spyCertificatesHandler: SpyCertificatesHandler
    private lateinit var certificateCredentialValue: CertificateCredentialValue

    private lateinit var certificateId: UUID
    private lateinit var name: String
    private lateinit var createdAt: Instant
    private lateinit var certificateCredentialVersion: CertificateCredentialVersion
    private lateinit var certificateView: CertificateView
    private val objectMapper: ObjectMapper = ObjectMapper()
    private lateinit var metadata: JsonNode

    companion object {
        @BeforeClass
        @JvmStatic
        fun setUpAll() {
            BouncyCastleFipsConfigurer.configure()
        }
    }

    @Before
    fun setUp() {
        spyCertificatesHandler = SpyCertificatesHandler()

        val certificateController =
            CertificatesController(
                spyCertificatesHandler,
                CEFAuditRecord(),
            )

        mockMvc = MockMvcFactory.newSpringRestDocMockMvc(certificateController, restDocumentation)
        metadata = objectMapper.readTree("{\"description\":\"example metadata\"}")

        if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleFipsProvider())
        }

        certificateId = UUID.randomUUID()
        name = "/some-name"
        createdAt = Instant.ofEpochSecond(1549053472L)

        certificateCredentialValue =
            CertificateCredentialValue(
                TestConstants.TEST_CA,
                TestConstants.TEST_CERTIFICATE,
                TestConstants.TEST_PRIVATE_KEY,
                name,
                false,
                false,
                true,
                true,
            )

        certificateCredentialVersion = CertificateCredentialVersion(certificateCredentialValue, name, SpyEncryptor())
        certificateCredentialVersion.versionCreatedAt = createdAt
        certificateCredentialVersion.uuid = certificateId
        certificateCredentialVersion.expiryDate = certificateCredentialValue.expiryDate
        certificateCredentialVersion.metadata = metadata

        certificateView = CertificateView(certificateCredentialVersion)
    }

    @Test
    fun postCertificatesUuidRegenerateReturnsCertificate() {
        // language=json
        val requestBody =
            """
            {"set_as_transitional": true, "allow_transitional_parent_to_sign": true, "key_length": 2048, "metadata": {"description": "example metadata"}}
            """.trimIndent()
        certificateView = CertificateGenerationView(certificateCredentialVersion, false)
        (certificateView as CertificateGenerationView).durationOverridden = true
        (certificateView as CertificateGenerationView).durationUsed = 1234
        spyCertificatesHandler.handleregenerateReturnsCredentialview = certificateView

        val mvcResult =
            mockMvc
                .perform(
                    post("${CertificatesController.ENDPOINT}/{certificateId}/regenerate", certificateId.toString())
                        .credHubAuthHeader()
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody),
                ).andExpect(status().isOk)
                .andDo(
                    document(
                        CredHubRestDocs.DOCUMENT_IDENTIFIER,
                        requestFields(
                            fieldWithPath("set_as_transitional")
                                .description("Set if certificate is transitional")
                                .type(JsonFieldType.BOOLEAN)
                                .optional(),
                            fieldWithPath("allow_transitional_parent_to_sign")
                                .description(
                                    "Allows a transitional version of the parent CA to sign this certificate if the transitional version is the latest version",
                                ).type(JsonFieldType.BOOLEAN)
                                .optional(),
                            fieldWithPath("key_length")
                                .description(
                                    "Set the key length for the regenerated certificate. If not provided, the key length will be the same as the original certificate.",
                                ).type(JsonFieldType.NUMBER)
                                .optional(),
                            fieldWithPath("metadata")
                                .description("Additional metadata of the credential.")
                                .optional(),
                            fieldWithPath("metadata.*")
                                .ignored(),
                        ),
                        pathParameters(
                            getCertificateIdPathParameter(),
                        ),
                    ),
                ).andReturn()

        val expectedRequestBody =
            CertificateRegenerateRequest(transitional = true, allowTransitionalParentToSign = true, keyLength = 2048, metadata = metadata)

        assertThat(spyCertificatesHandler.handleregenerateCalledwithRequest).isEqualTo(expectedRequestBody)
        assertThat(spyCertificatesHandler.handleregenerateCalledwithCredentialuuid).isEqualTo(certificateId.toString())

        // language=json
        val expectedResponseBody =
            """
            {
              "type": "${CredentialType.CERTIFICATE.type.lowercase()}",
              "version_created_at": "${certificateView.versionCreatedAt}",
              "id": "$certificateId",
              "name": "$name",
              "metadata": { "description": "example metadata"},
              "is_transitional": true,
              "generated": true,
              "expiry_date": "${certificateCredentialValue.expiryDate}",
              "certificate_authority": false,
              "self_signed": false,
              "duration_overridden": true,
              "duration_used": 1234,
              "key_length": 2048,
              "value": {
                "ca": "${TestConstants.TEST_CA}",
                "certificate": "${TestConstants.TEST_CERTIFICATE}",
                "private_key": "${TestConstants.TEST_PRIVATE_KEY}"
              }
            }
            """.trimIndent()
        JSONAssert.assertEquals(mvcResult.response.contentAsString, expectedResponseBody, true)
    }

    @Test
    fun `postCertificatesUuidRegenerateReturnsCertificate using invalid key size`() {
        // language=json
        val requestBody =
            """
            {"set_as_transitional": true, "allow_transitional_parent_to_sign": true, "key_length": 4711, "metadata": {"description": "example metadata"}}
            """.trimIndent()

        certificateView = CertificateGenerationView(certificateCredentialVersion, false)
        spyCertificatesHandler.handleregenerateReturnsCredentialview = CredentialView()

        var mvcResult =
            mockMvc
                .perform(
                    post("${CertificatesController.ENDPOINT}/{certificateId}/regenerate", certificateId.toString())
                        .credHubAuthHeader()
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody),
                ).andExpect(status().isBadRequest)
                .andReturn()

        val expectedRequestBody =
            CertificateRegenerateRequest(
                transitional = true,
                allowTransitionalParentToSign = true,
                keyLength = 4711,
                metadata = metadata,
            )

        assertThat(spyCertificatesHandler.handleregenerateCalledwithRequest).isEqualTo(expectedRequestBody)
        assertThat(spyCertificatesHandler.handleregenerateCalledwithCredentialuuid).isEqualTo(certificateId.toString())

        val expectedResponseBody =
            """
            {
              "error": "The provided key length is not supported. Valid values include '2048', '3072' and '4096'."
            }
            """.trimIndent()
        JSONAssert.assertEquals(mvcResult.response.contentAsString, expectedResponseBody, true)
    }

    @Test
    fun `postCertificatesUuidRegenerateReturnsCertificate generate a certificate with 4096 key length`() {
        val expectedCertificateCredentialValue =
            CertificateCredentialValue(
                TestConstants.TEST_CA_4096,
                TestConstants.TEST_CERTIFICATE_4096,
                TestConstants.TEST_PRIVATE_KEY_4096,
                name,
                false,
                false,
                true,
                true,
            )

        val expectedCertificateCredentialVersion = CertificateCredentialVersion(expectedCertificateCredentialValue, name, SpyEncryptor())
        expectedCertificateCredentialVersion.versionCreatedAt = createdAt
        expectedCertificateCredentialVersion.uuid = certificateId
        expectedCertificateCredentialVersion.metadata = metadata
        expectedCertificateCredentialVersion.expiryDate = certificateCredentialValue.expiryDate
        expectedCertificateCredentialVersion.durationOverridden = true
        expectedCertificateCredentialVersion.durationUsed = 1234

        val expectedCertificateView = CertificateGenerationView(expectedCertificateCredentialVersion, false)

        spyCertificatesHandler.handleregenerateReturnsCredentialview = expectedCertificateView

        // language=json
        val requestBody =
            """
            {"set_as_transitional": true, "allow_transitional_parent_to_sign": true, "key_length": 4096, "metadata": {"description": "example metadata"}}
            """.trimIndent()

        val mvcResult =
            mockMvc
                .perform(
                    post("${CertificatesController.ENDPOINT}/{certificateId}/regenerate", certificateId.toString())
                        .credHubAuthHeader()
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody),
                ).andExpect(status().isOk)
                .andDo(
                    document(
                        CredHubRestDocs.DOCUMENT_IDENTIFIER,
                        requestFields(
                            fieldWithPath("set_as_transitional")
                                .description("Set if certificate is transitional")
                                .type(JsonFieldType.BOOLEAN)
                                .optional(),
                            fieldWithPath("allow_transitional_parent_to_sign")
                                .description(
                                    "Allows a transitional version of the parent CA to sign this certificate if the transitional version is the latest version",
                                ).type(JsonFieldType.BOOLEAN)
                                .optional(),
                            fieldWithPath("key_length")
                                .description(
                                    "Set the key length for the regenerated certificate. If not provided, the key length will be the same as the original certificate.",
                                ).type(JsonFieldType.NUMBER)
                                .optional(),
                            fieldWithPath("metadata")
                                .description("Additional metadata of the credential.")
                                .optional(),
                            fieldWithPath("metadata.*")
                                .ignored(),
                        ),
                        pathParameters(
                            getCertificateIdPathParameter(),
                        ),
                    ),
                ).andReturn()

        val expectedRequestBody =
            CertificateRegenerateRequest(transitional = true, allowTransitionalParentToSign = true, keyLength = 4096, metadata = metadata)

        assertThat(spyCertificatesHandler.handleregenerateCalledwithRequest).isEqualTo(expectedRequestBody)
        assertThat(spyCertificatesHandler.handleregenerateCalledwithCredentialuuid).isEqualTo(certificateId.toString())

        // language=json
        val expectedResponseBody =
            """
            {
              "type": "${CredentialType.CERTIFICATE.type.lowercase()}",
              "version_created_at": "${certificateView.versionCreatedAt}",
              "id": "$certificateId",
              "name": "$name",
              "metadata": { "description": "example metadata"},
              "is_transitional": true,
              "generated": true,
              "expiry_date": "${certificateCredentialValue.expiryDate}",
              "certificate_authority": false,
              "self_signed": false,
              "duration_overridden": true,
              "duration_used": 1234,
              "key_length": 4096,
              "value": {
                "ca": "${TestConstants.TEST_CA_4096}",
                "certificate": "${TestConstants.TEST_CERTIFICATE_4096}",
                "private_key": "${TestConstants.TEST_PRIVATE_KEY_4096}"
              }
            }
            """.trimIndent()
        JSONAssert.assertEquals(mvcResult.response.contentAsString, expectedResponseBody, true)
    }

    @Test
    fun getCertificatesReturnsCertificates() {
        var caName = "/testCa"
        val certificateVersions =
            mutableListOf(
                CertificateVersionView(
                    id = UUID.randomUUID(),
                    transitional = true,
                    expiryDate = Instant.ofEpochSecond(1549053472L).plus(365, ChronoUnit.DAYS),
                    certificateAuthority = false,
                    selfSigned = false,
                    generated = false,
                ),
                CertificateVersionView(
                    id = UUID.randomUUID(),
                    transitional = false,
                    expiryDate = Instant.ofEpochSecond(1549053472L),
                    certificateAuthority = false,
                    selfSigned = false,
                    generated = false,
                ),
            )
        var cert1Name = "/cert1"
        var cert2Name = "/cert2"

        val certificateCredentialsView =
            CertificateCredentialsView(
                listOf(CertificateCredentialView(name, certificateId, certificateVersions, caName, listOf(cert1Name, cert2Name))),
            )
        spyCertificatesHandler.handlegetallrequestReturnsCertificatecredentialsview = certificateCredentialsView

        val mvcResult =
            mockMvc
                .perform(
                    get(CertificatesController.ENDPOINT)
                        .credHubAuthHeader()
                        .accept(MediaType.APPLICATION_JSON),
                ).andExpect(status().isOk)
                .andDo(
                    document(
                        CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    ),
                ).andReturn()

        // language=json
        val expectedResponse =
            """
            {
              "certificates": [
                {
                  "name": "$name",
                  "id": "$certificateId",
                  "signed_by": "$caName",
                  "signs": ["$cert1Name", "$cert2Name"],
                  "versions": [
                    {
                      "id": "${certificateVersions[0].id}",
                      "expiry_date": "2020-02-01T20:37:52Z",
                      "transitional": true,
                      "certificate_authority": false,
                      "self_signed": false,
                      "generated": false
                    },
                    {
                      "id": "${certificateVersions[1].id}",
                      "expiry_date": "2019-02-01T20:37:52Z",
                      "transitional": false,
                      "certificate_authority": false,
                      "self_signed": false,
                      "generated": false
                    }
                  ]
                }
              ]
            }
            """.trimIndent()

        JSONAssert.assertEquals(mvcResult.response.contentAsString, expectedResponse, true)
    }

    @Test
    fun getCertificatesWhenGeneratedisNullReturnsCertificatesCertificateWithoutGeneratedField() {
        var caName = "/testCa"
        val certificateVersions =
            mutableListOf(
                CertificateVersionView(
                    id = UUID.randomUUID(),
                    transitional = true,
                    expiryDate = Instant.ofEpochSecond(1549053472L).plus(365, ChronoUnit.DAYS),
                    certificateAuthority = false,
                    selfSigned = false,
                    generated = null,
                ),
            )
        var cert1Name = "/cert1"
        var cert2Name = "/cert2"

        val certificateCredentialsView =
            CertificateCredentialsView(
                listOf(CertificateCredentialView(name, certificateId, certificateVersions, caName, listOf(cert1Name, cert2Name))),
            )
        spyCertificatesHandler.handlegetallrequestReturnsCertificatecredentialsview = certificateCredentialsView

        val mvcResult =
            mockMvc
                .perform(
                    get(CertificatesController.ENDPOINT)
                        .credHubAuthHeader()
                        .accept(MediaType.APPLICATION_JSON),
                ).andExpect(status().isOk)
                .andReturn()

        // language=json
        val expectedResponse =
            """
            {
              "certificates": [
                {
                  "name": "$name",
                  "id": "$certificateId",
                  "signed_by": "$caName",
                  "signs": ["$cert1Name", "$cert2Name"],
                  "versions": [
                    {
                      "id": "${certificateVersions[0].id}",
                      "expiry_date": "2020-02-01T20:37:52Z",
                      "transitional": true,
                      "certificate_authority": false,
                      "self_signed": false
                    }
                  ]
                }
              ]
            }
            """.trimIndent()

        JSONAssert.assertEquals(expectedResponse, mvcResult.response.contentAsString, true)
    }

    @Test
    fun getCertificatesWhenExpiryDateisNullReturnsCertificatesCertificateWithEmptyExpiryDateField() {
        var caName = "/testCa"
        val certificateVersions =
            mutableListOf(
                CertificateVersionView(
                    id = UUID.randomUUID(),
                    transitional = true,
                    expiryDate = null,
                    certificateAuthority = false,
                    selfSigned = false,
                    generated = true,
                ),
            )
        var cert1Name = "/cert1"
        var cert2Name = "/cert2"

        val certificateCredentialsView =
            CertificateCredentialsView(
                listOf(CertificateCredentialView(name, certificateId, certificateVersions, caName, listOf(cert1Name, cert2Name))),
            )
        spyCertificatesHandler.handlegetallrequestReturnsCertificatecredentialsview = certificateCredentialsView

        val mvcResult =
            mockMvc
                .perform(
                    get(CertificatesController.ENDPOINT)
                        .credHubAuthHeader()
                        .accept(MediaType.APPLICATION_JSON),
                ).andExpect(status().isOk)
                .andReturn()

        // language=json
        val expectedResponse =
            """
            {
              "certificates": [
                {
                  "name": "$name",
                  "id": "$certificateId",
                  "signed_by": "$caName",
                  "signs": ["$cert1Name", "$cert2Name"],
                  "versions": [
                    {
                      "id": "${certificateVersions[0].id}",
                      "expiry_date": "",
                      "transitional": true,
                      "certificate_authority": false,
                      "self_signed": false,
                      "generated": true
                    }
                  ]
                }
              ]
            }
            """.trimIndent()

        JSONAssert.assertEquals(expectedResponse, mvcResult.response.contentAsString, true)
    }

    @Test
    fun getCertificatesByNameReturnsCertificate() {
        var caName = "/testCa"
        val certificateVersions =
            mutableListOf(
                CertificateVersionView(
                    id = UUID.randomUUID(),
                    transitional = false,
                    expiryDate = Instant.ofEpochSecond(1549053472L),
                    certificateAuthority = false,
                    selfSigned = false,
                    generated = false,
                ),
            )
        var cert1Name = "/cert1"
        var cert2Name = "/cert2"

        val certificateCredentialsView =
            CertificateCredentialsView(
                listOf(CertificateCredentialView(name, certificateId, certificateVersions, caName, listOf(cert1Name, cert2Name))),
            )
        spyCertificatesHandler.handlegetbynamerequestReturnsCertificatecredentialsview = certificateCredentialsView

        val mvcResult =
            mockMvc
                .perform(
                    get(CertificatesController.ENDPOINT)
                        .credHubAuthHeader()
                        .accept(MediaType.APPLICATION_JSON)
                        .param("name", name),
                ).andExpect(status().isOk)
                .andDo(
                    document(
                        CredHubRestDocs.DOCUMENT_IDENTIFIER,
                        queryParameters(parameterWithName("name").description("The name of the certificate.")),
                    ),
                ).andReturn()

        // language=json
        val expectedResponse =
            """
            {
              "certificates":
              [
                {
                  "name":"$name",
                  "id":"$certificateId",
                  "signed_by": "$caName",
                  "signs": ["$cert1Name", "$cert2Name"],
                  "versions": [
                    {
                      "id": "${certificateVersions[0].id}",
                      "expiry_date": "2019-02-01T20:37:52Z",
                      "transitional": false,
                      "generated": false,
                      "certificate_authority": false,
                      "self_signed": false
                    }
                  ]
                }
              ]
            }
            """.trimIndent()

        JSONAssert.assertEquals(mvcResult.response.contentAsString, expectedResponse, true)
    }

    @Test
    fun getCertificatesByNameWhenGeneratedIsNullReturnsCcertificateWithoutGeneratedField() {
        var caName = "/testCa"
        val certificateVersions =
            mutableListOf(
                CertificateVersionView(
                    id = UUID.randomUUID(),
                    transitional = false,
                    expiryDate = Instant.ofEpochSecond(1549053472L),
                    certificateAuthority = false,
                    selfSigned = false,
                    generated = null,
                ),
            )
        var cert1Name = "/cert1"
        var cert2Name = "/cert2"

        val certificateCredentialsView =
            CertificateCredentialsView(
                listOf(CertificateCredentialView(name, certificateId, certificateVersions, caName, listOf(cert1Name, cert2Name))),
            )
        spyCertificatesHandler.handlegetbynamerequestReturnsCertificatecredentialsview = certificateCredentialsView

        val mvcResult =
            mockMvc
                .perform(
                    get(CertificatesController.ENDPOINT)
                        .credHubAuthHeader()
                        .accept(MediaType.APPLICATION_JSON)
                        .param("name", name),
                ).andExpect(status().isOk)
                .andReturn()

        // language=json
        val expectedResponse =
            """
            {
              "certificates":
              [
                {
                  "name":"$name",
                  "id":"$certificateId",
                  "signed_by": "$caName",
                  "signs": ["$cert1Name", "$cert2Name"],
                  "versions": [
                    {
                      "id": "${certificateVersions[0].id}",
                      "expiry_date": "2019-02-01T20:37:52Z",
                      "transitional": false,
                      "certificate_authority": false,
                      "self_signed": false
                    }
                  ]
                }
              ]
            }
            """.trimIndent()

        JSONAssert.assertEquals(mvcResult.response.contentAsString, expectedResponse, true)
    }

    @Test
    fun putUpdateTransitionalVersionReturnsCertificate() {
        val versionId = UUID.randomUUID()

        // language=json
        val requestBody =
            """
            {"version": "$versionId"}
            """.trimIndent()

        spyCertificatesHandler.handleupdatetransitionalversionReturnsCertificateviewlist = listOf(certificateView)

        mockMvc
            .perform(
                put("${CertificatesController.ENDPOINT}/{certificateId}/update_transitional_version", certificateId.toString())
                    .credHubAuthHeader()
                    .accept(MediaType.APPLICATION_JSON)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(requestBody),
            ).andExpect(status().isOk)
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    requestFields(
                        fieldWithPath("version")
                            .description(
                                "Version UUID of certificate to set as transitional. Set version to null to ensure no versions are transitional.",
                            ).type(JsonFieldType.STRING),
                    ),
                    pathParameters(
                        getCertificateIdPathParameter(),
                    ),
                ),
            ).andReturn()

        val actualRequestBody = spyCertificatesHandler.handleupdatetransitionalversionCalledwithRequestbody
        val expectedRequestBody = UpdateTransitionalVersionRequest(versionId.toString())

        assertThat(spyCertificatesHandler.handleupdatetransitionalversionCalledwithCertificateid).isEqualTo(certificateId.toString())
        assertThat(expectedRequestBody).isEqualTo(actualRequestBody)
    }

    @Test
    fun getCertificateVersionsReturnsCertificates() {
        spyCertificatesHandler.handlegetallversionsrequestReturnsCertificateviews = listOf(certificateView)

        val mvcResult =
            mockMvc
                .perform(
                    get("${CertificatesController.ENDPOINT}/{certificateId}/versions", certificateId.toString())
                        .credHubAuthHeader()
                        .accept(MediaType.APPLICATION_JSON)
                        .param("current", "true"),
                ).andExpect(status().isOk)
                .andDo(
                    document(
                        CredHubRestDocs.DOCUMENT_IDENTIFIER,
                        queryParameters(
                            parameterWithName("current")
                                .description("Return current active version")
                                .optional(),
                        ),
                        pathParameters(
                            getCertificateIdPathParameter(),
                        ),
                    ),
                ).andReturn()

        assertThat(spyCertificatesHandler.handlegetallversionsrequestCalledwithCurrent).isTrue()
        assertThat(spyCertificatesHandler.handlegetallversionsrequestCalledwithUuid).isEqualTo(certificateId.toString())

        // language=json
        val expectedResponseBody =
            """
            [{
              "type": "${CredentialType.CERTIFICATE.type.lowercase()}",
              "version_created_at": "${certificateView.versionCreatedAt}",
              "id": "$certificateId",
              "name": "$name",
              "is_transitional": true,
              "generated": true,
              "certificate_authority": false,
              "self_signed": false,
              "expiry_date": "${certificateCredentialValue.expiryDate}",
              "metadata": { "description": "example metadata"},
              "value": {
                "ca": "${TestConstants.TEST_CA}",
                "certificate": "${TestConstants.TEST_CERTIFICATE}",
                "private_key": "${TestConstants.TEST_PRIVATE_KEY}"
              }
            }]
            """.trimIndent()

        val contentAsString = mvcResult.response.contentAsString
        JSONAssert.assertEquals(expectedResponseBody, contentAsString, true)
    }

    @Test
    fun getCertificateVersionsWhenGeneratedIsNullReturnsCertificatesWithoutGeneratedField() {
        val value =
            CertificateCredentialValue(
                TestConstants.TEST_CA,
                TestConstants.TEST_CERTIFICATE,
                TestConstants.TEST_PRIVATE_KEY,
                name,
                false,
                false,
                null,
                true,
            )

        val credentialVersion = CertificateCredentialVersion(value, name, SpyEncryptor())
        credentialVersion.expiryDate = certificateCredentialValue.expiryDate
        credentialVersion.versionCreatedAt = createdAt
        credentialVersion.uuid = certificateId
        credentialVersion.metadata = metadata
        val nullGeneratedView = CertificateView(credentialVersion)

        spyCertificatesHandler.handlegetallversionsrequestReturnsCertificateviews = listOf(nullGeneratedView)

        val mvcResult =
            mockMvc
                .perform(
                    get("${CertificatesController.ENDPOINT}/{certificateId}/versions", certificateId.toString())
                        .credHubAuthHeader()
                        .accept(MediaType.APPLICATION_JSON)
                        .param("current", "true"),
                ).andExpect(status().isOk)
                .andReturn()

        assertThat(spyCertificatesHandler.handlegetallversionsrequestCalledwithCurrent).isTrue()
        assertThat(spyCertificatesHandler.handlegetallversionsrequestCalledwithUuid).isEqualTo(certificateId.toString())

        // language=json
        val expectedResponseBody =
            """
            [{
              "type": "${CredentialType.CERTIFICATE.type.lowercase()}",
              "version_created_at": "${certificateView.versionCreatedAt}",
              "id": "$certificateId",
              "name": "$name",
              "is_transitional": true,
              "certificate_authority": false,
              "self_signed": false,
              "expiry_date": "${certificateCredentialValue.expiryDate}", 
              "metadata": { "description": "example metadata"},
              "value": {
                "ca": "${TestConstants.TEST_CA}",
                "certificate": "${TestConstants.TEST_CERTIFICATE}",
                "private_key": "${TestConstants.TEST_PRIVATE_KEY}"
              }
            }]
            """.trimIndent()

        val contentAsString = mvcResult.response.contentAsString
        JSONAssert.assertEquals(expectedResponseBody, contentAsString, true)
    }

    @Test
    fun getCertificateVersionsReturnsCertificate() {
        val expectedCertificateCredentialValue =
            CertificateCredentialValue(
                TestConstants.TEST_CA,
                TestConstants.TEST_CERTIFICATE,
                TestConstants.TEST_PRIVATE_KEY,
                name,
                false,
                false,
                false,
                true,
            )

        val expectedCertificateCredentialVersion = CertificateCredentialVersion(expectedCertificateCredentialValue, name, SpyEncryptor())
        expectedCertificateCredentialVersion.versionCreatedAt = createdAt
        expectedCertificateCredentialVersion.uuid = certificateId
        expectedCertificateCredentialVersion.metadata = metadata
        expectedCertificateCredentialVersion.expiryDate = expectedCertificateCredentialValue.expiryDate

        val expectedCertificateView = CertificateView(expectedCertificateCredentialVersion)
        spyCertificatesHandler.handlecreateversionrequestReturnsCertificateview = expectedCertificateView

        // language=json
        val requestBody =
            """
            {
              "value": {
                "ca": "${JsonHelpers.escapeNewLinesForJsonSerialization(TestConstants.TEST_CA)}",
                "certificate": "${JsonHelpers.escapeNewLinesForJsonSerialization(TestConstants.TEST_CERTIFICATE)}",
                "private_key": "${JsonHelpers.escapeNewLinesForJsonSerialization(TestConstants.TEST_PRIVATE_KEY)}"
              },
              "transitional": true
            }
            """.trimIndent()

        val mvcResult =
            mockMvc
                .perform(
                    post("${CertificatesController.ENDPOINT}/{certificateId}/versions", certificateId.toString())
                        .credHubAuthHeader()
                        .accept(MediaType.APPLICATION_JSON)
                        .characterEncoding("utf-8")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody),
                ).andExpect(status().isOk)
                .andDo(
                    document(
                        CredHubRestDocs.DOCUMENT_IDENTIFIER,
                        pathParameters(
                            getCertificateIdPathParameter(),
                        ),
                    ),
                ).andReturn()

        JSONAssert.assertEquals(mvcResult.request.contentAsString, requestBody, true)
        assertThat(spyCertificatesHandler.handlecreateversionrequestCalledwithCertificateid).isEqualTo(certificateId.toString())

        // language=json
        val expectedResponseBody =
            """
            {
              "type": "${CredentialType.CERTIFICATE.type.lowercase()}",
              "version_created_at": "$createdAt",
              "id": "$certificateId",
              "name": "$name",
              "is_transitional": true,
              "certificate_authority": false,
              "self_signed": false,
              "generated": false,
              "expiry_date": "${expectedCertificateCredentialValue.expiryDate}",
              "metadata": { "description": "example metadata"},
              "value": {
                "ca": "${TestConstants.TEST_CA}",
                "certificate": "${TestConstants.TEST_CERTIFICATE}",
                "private_key": "${TestConstants.TEST_PRIVATE_KEY}"
              }
            }
            """.trimIndent()

        val contentAsString = mvcResult.response.contentAsString
        JSONAssert.assertEquals(expectedResponseBody, contentAsString, true)
    }

    @Test
    fun deleteRertificateVersionReturnsCertificate() {
        val versionId = UUID.randomUUID()
        spyCertificatesHandler.handledeleteversionrequestReturnsCertificateview = certificateView

        val mvcResult =
            mockMvc
                .perform(
                    delete(
                        "${CertificatesController.ENDPOINT}/{certificateId}/versions/{versionId}",
                        certificateId.toString(),
                        versionId.toString(),
                    ).credHubAuthHeader()
                        .accept(MediaType.APPLICATION_JSON),
                ).andExpect(status().isOk)
                .andDo(
                    document(
                        CredHubRestDocs.DOCUMENT_IDENTIFIER,
                        pathParameters(
                            getCertificateIdPathParameter(),
                            parameterWithName("versionId").description("Version Id"),
                        ),
                    ),
                ).andReturn()

        assertThat(spyCertificatesHandler.handledeleteversionrequestCalledwithCertificateid).isEqualTo(certificateId.toString())
        assertThat(spyCertificatesHandler.handledeleteversionrequestCalledwithVersionid).isEqualTo(versionId.toString())

        // language=json
        val expectedResponseBody =
            """
            {
              "type": "${CredentialType.CERTIFICATE.type.lowercase()}",
              "version_created_at": "${certificateView.versionCreatedAt}",
              "id": "$certificateId",
              "name": "$name",
              "is_transitional": true,
              "certificate_authority": false,
              "self_signed": false,
              "generated": true,
              "expiry_date": "${certificateCredentialValue.expiryDate}",
              "metadata": { "description": "example metadata"},
              "value": {
                "ca": "${TestConstants.TEST_CA}",
                "certificate": "${TestConstants.TEST_CERTIFICATE}",
                "private_key": "${TestConstants.TEST_PRIVATE_KEY}"
              }
            }
            """.trimIndent()

        val contentAsString = mvcResult.response.contentAsString
        JSONAssert.assertEquals(expectedResponseBody, contentAsString, true)
    }

    private fun getCertificateIdPathParameter(): ParameterDescriptor =
        parameterWithName("certificateId").description("The certificate identifier.")
}
