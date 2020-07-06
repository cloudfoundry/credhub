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
import org.cloudfoundry.credhub.utils.TestConstants
import org.cloudfoundry.credhub.views.CertificateCredentialView
import org.cloudfoundry.credhub.views.CertificateCredentialsView
import org.cloudfoundry.credhub.views.CertificateVersionView
import org.cloudfoundry.credhub.views.CertificateView
import org.cloudfoundry.credhub.views.CredentialView
import org.junit.Before
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
import org.springframework.restdocs.request.RequestDocumentation.requestParameters
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
    private lateinit var credentialViewResponse: CredentialView

    private lateinit var certificateId: UUID
    private lateinit var name: String
    private lateinit var createdAt: Instant
    private lateinit var certificateCredentialVersion: CertificateCredentialVersion
    private lateinit var certificateView: CertificateView
    private val objectMapper: ObjectMapper = ObjectMapper()
    private lateinit var metadata: JsonNode

    @Before
    fun setUp() {
        spyCertificatesHandler = SpyCertificatesHandler()

        val certificateController = CertificatesController(
            spyCertificatesHandler,
            CEFAuditRecord()
        )

        mockMvc = MockMvcFactory.newSpringRestDocMockMvc(certificateController, restDocumentation)
        metadata = objectMapper.readTree("{\"description\":\"example metadata\"}")

        if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleFipsProvider())
        }

        certificateId = UUID.randomUUID()
        name = "/some-name"
        createdAt = Instant.ofEpochSecond(1549053472L)

        certificateCredentialValue = CertificateCredentialValue(
            TestConstants.TEST_CA,
            TestConstants.TEST_CERTIFICATE,
            TestConstants.TEST_PRIVATE_KEY,
            name,
            false,
            false,
            true,
            true
        )

        credentialViewResponse = CredentialView(
            createdAt,
            certificateId,
            name,
            CredentialType.CERTIFICATE.type.toLowerCase(),
            metadata,
            certificateCredentialValue
        )

        certificateCredentialVersion = CertificateCredentialVersion(certificateCredentialValue, name, SpyEncryptor())
        certificateCredentialVersion.versionCreatedAt = createdAt
        certificateCredentialVersion.uuid = certificateId
        certificateCredentialVersion.expiryDate = certificateCredentialValue.expiryDate
        certificateCredentialVersion.metadata = metadata

        certificateView = CertificateView(certificateCredentialVersion)
    }

    @Test
    fun POST__certificates_uuid_regenerate__returns_certificate() {
        // language=json
        val requestBody =
            """
            {"set_as_transitional": true, "allow_transitional_parent_to_sign": true, "metadata": {"description": "example metadata"}}
            """.trimIndent()

        spyCertificatesHandler.handleRegenerate__returns_credentialView = credentialViewResponse

        val mvcResult = mockMvc
            .perform(
                post("${CertificatesController.ENDPOINT}/{certificateId}/regenerate", certificateId.toString())
                    .credHubAuthHeader()
                    .accept(MediaType.APPLICATION_JSON_UTF8)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(requestBody)
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
                            .description("Allows a transitional version of the parent CA to sign this certificate if the transitional version is the latest version")
                            .type(JsonFieldType.BOOLEAN)
                            .optional(),
                        fieldWithPath("metadata")
                            .description("Additional metadata of the credential.")
                            .optional(),
                        fieldWithPath("metadata.*")
                            .ignored()
                    ),
                    pathParameters(
                        getCertificateIdPathParameter()
                    )
                )

            ).andReturn()

        val expectedRequestBody = CertificateRegenerateRequest(transitional = true, allowTransitionalParentToSign = true, metadata = metadata)

        assertThat(spyCertificatesHandler.handleRegenerate__calledWith_request).isEqualTo(expectedRequestBody)
        assertThat(spyCertificatesHandler.handleRegenerate__calledWith_credentialUuid).isEqualTo(certificateId.toString())

        // language=json
        val expectedResponseBody =
            """
            {
              "type": "${CredentialType.CERTIFICATE.type.toLowerCase()}",
              "version_created_at": "${credentialViewResponse.versionCreatedAt}",
              "id": "$certificateId",
              "name": "$name",
              "metadata": { "description": "example metadata"},
              "value": {
                "ca": "${TestConstants.TEST_CA}",
                "certificate": "${TestConstants.TEST_CERTIFICATE}",
                "private_key": "${TestConstants.TEST_PRIVATE_KEY}",
                "transitional": true,
                "generated": true,
                "expiry_date": "${certificateCredentialValue.expiryDate}",
                "certificate_authority": false,
                "self_signed": false
              }
            }
            """.trimIndent()
        JSONAssert.assertEquals(mvcResult.response.contentAsString, expectedResponseBody, true)
    }

    @Test
    fun GET__certificates__returns_certificates() {
        var caName = "/testCa"
        val certificateVersions = mutableListOf(
            CertificateVersionView(
                id = UUID.randomUUID(),
                transitional = true,
                expiryDate = Instant.ofEpochSecond(1549053472L).plus(365, ChronoUnit.DAYS),
                certificateAuthority = false,
                selfSigned = false,
                generated = false
            ),
            CertificateVersionView(
                id = UUID.randomUUID(),
                transitional = false,
                expiryDate = Instant.ofEpochSecond(1549053472L),
                certificateAuthority = false,
                selfSigned = false,
                generated = false
            )
        )
        var cert1Name = "/cert1"
        var cert2Name = "/cert2"

        val certificateCredentialsView = CertificateCredentialsView(
            listOf(CertificateCredentialView(name, certificateId, certificateVersions, caName, listOf(cert1Name, cert2Name)))
        )
        spyCertificatesHandler.handleGetAllRequest__returns_certificateCredentialsView = certificateCredentialsView

        val mvcResult = mockMvc
            .perform(
                get(CertificatesController.ENDPOINT)
                    .credHubAuthHeader()
                    .accept(MediaType.APPLICATION_JSON_UTF8)
            ).andExpect(status().isOk)
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER
                )
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
    fun GET__certificates_whenGeneratedisNull_returns_certificates_certificateWithoutGeneratedField() {
        var caName = "/testCa"
        val certificateVersions = mutableListOf(
            CertificateVersionView(
                id = UUID.randomUUID(),
                transitional = true,
                expiryDate = Instant.ofEpochSecond(1549053472L).plus(365, ChronoUnit.DAYS),
                certificateAuthority = false,
                selfSigned = false,
                generated = null
            )
        )
        var cert1Name = "/cert1"
        var cert2Name = "/cert2"

        val certificateCredentialsView = CertificateCredentialsView(
            listOf(CertificateCredentialView(name, certificateId, certificateVersions, caName, listOf(cert1Name, cert2Name)))
        )
        spyCertificatesHandler.handleGetAllRequest__returns_certificateCredentialsView = certificateCredentialsView

        val mvcResult = mockMvc
            .perform(
                get(CertificatesController.ENDPOINT)
                    .credHubAuthHeader()
                    .accept(MediaType.APPLICATION_JSON_UTF8)
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
    fun GET__certificates_whenExpiryDateisNull_returns_certificates_certificateWithEmptyExpiryDateField() {
        var caName = "/testCa"
        val certificateVersions = mutableListOf(
            CertificateVersionView(
                id = UUID.randomUUID(),
                transitional = true,
                expiryDate = null,
                certificateAuthority = false,
                selfSigned = false,
                generated = true
            )
        )
        var cert1Name = "/cert1"
        var cert2Name = "/cert2"

        val certificateCredentialsView = CertificateCredentialsView(
            listOf(CertificateCredentialView(name, certificateId, certificateVersions, caName, listOf(cert1Name, cert2Name)))
        )
        spyCertificatesHandler.handleGetAllRequest__returns_certificateCredentialsView = certificateCredentialsView

        val mvcResult = mockMvc
            .perform(
                get(CertificatesController.ENDPOINT)
                    .credHubAuthHeader()
                    .accept(MediaType.APPLICATION_JSON_UTF8)
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
    fun GET__certificates_byName__returns_certificate() {
        var caName = "/testCa"
        val certificateVersions = mutableListOf(
            CertificateVersionView(
                id = UUID.randomUUID(),
                transitional = false,
                expiryDate = Instant.ofEpochSecond(1549053472L),
                certificateAuthority = false,
                selfSigned = false,
                generated = false
            )
        )
        var cert1Name = "/cert1"
        var cert2Name = "/cert2"

        val certificateCredentialsView = CertificateCredentialsView(
            listOf(CertificateCredentialView(name, certificateId, certificateVersions, caName, listOf(cert1Name, cert2Name)))
        )
        spyCertificatesHandler.handleGetByNameRequest__returns_certificateCredentialsView = certificateCredentialsView

        val mvcResult = mockMvc
            .perform(
                get(CertificatesController.ENDPOINT)
                    .credHubAuthHeader()
                    .accept(MediaType.APPLICATION_JSON_UTF8)
                    .param("name", name)
            ).andExpect(status().isOk)
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    requestParameters(parameterWithName("name").description("The name of the certificate."))
                )
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
    fun GET__certificates_byName__WhenGeneratedIsNull_returns_certificateWithoutGeneratedField() {
        var caName = "/testCa"
        val certificateVersions = mutableListOf(
            CertificateVersionView(
                id = UUID.randomUUID(),
                transitional = false,
                expiryDate = Instant.ofEpochSecond(1549053472L),
                certificateAuthority = false,
                selfSigned = false,
                generated = null
            )
        )
        var cert1Name = "/cert1"
        var cert2Name = "/cert2"

        val certificateCredentialsView = CertificateCredentialsView(
            listOf(CertificateCredentialView(name, certificateId, certificateVersions, caName, listOf(cert1Name, cert2Name)))
        )
        spyCertificatesHandler.handleGetByNameRequest__returns_certificateCredentialsView = certificateCredentialsView

        val mvcResult = mockMvc
            .perform(
                get(CertificatesController.ENDPOINT)
                    .credHubAuthHeader()
                    .accept(MediaType.APPLICATION_JSON_UTF8)
                    .param("name", name)
            ).andExpect(status().isOk).andReturn()

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
    fun PUT__updateTransitionalVersion__returns_certificate() {
        val versionId = UUID.randomUUID()

        // language=json
        val requestBody =
            """
            {"version": "$versionId"}
            """.trimIndent()

        spyCertificatesHandler.handleUpdateTransitionalVersion__returns_certificateViewList = listOf(certificateView)

        mockMvc
            .perform(
                put("${CertificatesController.ENDPOINT}/{certificateId}/update_transitional_version", certificateId.toString())
                    .credHubAuthHeader()
                    .accept(MediaType.APPLICATION_JSON_UTF8)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(requestBody)
            ).andExpect(status().isOk)
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    requestFields(
                        fieldWithPath("version")
                            .description("Version UUID of certificate to set as transitional. Set version to null to ensure no versions are transitional.")
                            .type(JsonFieldType.STRING)
                    ),
                    pathParameters(
                        getCertificateIdPathParameter()
                    )
                )

            ).andReturn()

        val actualRequestBody = spyCertificatesHandler.handleUpdateTransitionalVersion__calledWith_requestBody
        val expectedRequestBody = UpdateTransitionalVersionRequest(versionId.toString())

        assertThat(spyCertificatesHandler.handleUpdateTransitionalVersion__calledWith_certificateId).isEqualTo(certificateId.toString())
        assertThat(expectedRequestBody).isEqualTo(actualRequestBody)
    }

    @Test
    fun GET__certificateVersions__returns_certificates() {
        spyCertificatesHandler.handleGetAllVersionsRequest__returns_certificateViews = listOf(certificateView)

        val mvcResult = mockMvc.perform(
            get("${CertificatesController.ENDPOINT}/{certificateId}/versions", certificateId.toString())
                .credHubAuthHeader()
                .accept(MediaType.APPLICATION_JSON_UTF8)
                .param("current", "true")
        ).andExpect(status().isOk)
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    requestParameters(
                        parameterWithName("current").description("Return current active version")
                            .optional()
                    ),
                    pathParameters(
                        getCertificateIdPathParameter()
                    )
                )
            ).andReturn()

        assertThat(spyCertificatesHandler.handleGetAllVersionsRequest__calledWith_current).isTrue()
        assertThat(spyCertificatesHandler.handleGetAllVersionsRequest__calledWith_uuid).isEqualTo(certificateId.toString())

        // language=json
        val expectedResponseBody =
            """
            [{
              "type": "${CredentialType.CERTIFICATE.type.toLowerCase()}",
              "version_created_at": "${credentialViewResponse.versionCreatedAt}",
              "id": "$certificateId",
              "name": "$name",
              "transitional": true,
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
    fun GET__certificateVersions__WhenGeneratedIsNull_returns_certificatesWithoutGeneratedField() {

        val value = CertificateCredentialValue(
            TestConstants.TEST_CA,
            TestConstants.TEST_CERTIFICATE,
            TestConstants.TEST_PRIVATE_KEY,
            name,
            false,
            false,
            null,
            true
        )

        val credentialVersion = CertificateCredentialVersion(value, name, SpyEncryptor())
        credentialVersion.expiryDate = certificateCredentialValue.expiryDate
        credentialVersion.versionCreatedAt = createdAt
        credentialVersion.uuid = certificateId
        credentialVersion.metadata = metadata
        val nullGeneratedView = CertificateView(credentialVersion)

        spyCertificatesHandler.handleGetAllVersionsRequest__returns_certificateViews = listOf(nullGeneratedView)

        val mvcResult = mockMvc.perform(
            get("${CertificatesController.ENDPOINT}/{certificateId}/versions", certificateId.toString())
                .credHubAuthHeader()
                .accept(MediaType.APPLICATION_JSON_UTF8)
                .param("current", "true")
        ).andExpect(status().isOk).andReturn()

        assertThat(spyCertificatesHandler.handleGetAllVersionsRequest__calledWith_current).isTrue()
        assertThat(spyCertificatesHandler.handleGetAllVersionsRequest__calledWith_uuid).isEqualTo(certificateId.toString())

        // language=json
        val expectedResponseBody =
            """
            [{
              "type": "${CredentialType.CERTIFICATE.type.toLowerCase()}",
              "version_created_at": "${credentialViewResponse.versionCreatedAt}",
              "id": "$certificateId",
              "name": "$name",
              "transitional": true,
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
    fun POST__certificateVersions__returns_certificate() {
        val expectedCertificateCredentialValue = CertificateCredentialValue(
            TestConstants.TEST_CA,
            TestConstants.TEST_CERTIFICATE,
            TestConstants.TEST_PRIVATE_KEY,
            name,
            false,
            false,
            false,
            true
        )

        val expectedCredentialViewResponse = CredentialView(
            createdAt,
            certificateId,
            name,
            CredentialType.CERTIFICATE.type.toLowerCase(),
            null,
            expectedCertificateCredentialValue
        )

        val expectedCertificateCredentialVersion = CertificateCredentialVersion(expectedCertificateCredentialValue, name, SpyEncryptor())
        expectedCertificateCredentialVersion.versionCreatedAt = createdAt
        expectedCertificateCredentialVersion.uuid = certificateId
        expectedCertificateCredentialVersion.metadata = metadata
        expectedCertificateCredentialVersion.expiryDate = expectedCertificateCredentialValue.expiryDate

        val expectedCertificateView = CertificateView(expectedCertificateCredentialVersion)
        spyCertificatesHandler.handleCreateVersionRequest__returns_certificateView = expectedCertificateView

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

        val mvcResult = mockMvc.perform(
            post("${CertificatesController.ENDPOINT}/{certificateId}/versions", certificateId.toString())
                .credHubAuthHeader()
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_JSON_UTF8)
                .content(requestBody)
        ).andExpect(status().isOk)
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    pathParameters(
                        getCertificateIdPathParameter()
                    )
                )
            ).andReturn()

        JSONAssert.assertEquals(mvcResult.request.contentAsString, requestBody, true)
        assertThat(spyCertificatesHandler.handleCreateVersionRequest__calledWith_certificateId).isEqualTo(certificateId.toString())

        // language=json
        val expectedResponseBody =
            """
            {
              "type": "${CredentialType.CERTIFICATE.type.toLowerCase()}",
              "version_created_at": "${expectedCredentialViewResponse.versionCreatedAt}",
              "id": "$certificateId",
              "name": "$name",
              "transitional": true,
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
    fun DELETE__certificateVersion__returns_certificate() {
        val versionId = UUID.randomUUID()
        spyCertificatesHandler.handleDeleteVersionRequest__returns_certificateView = certificateView

        val mvcResult = mockMvc.perform(
            delete("${CertificatesController.ENDPOINT}/{certificateId}/versions/{versionId}", certificateId.toString(), versionId.toString())
                .credHubAuthHeader()
                .accept(MediaType.APPLICATION_JSON_UTF8)
        ).andExpect(status().isOk)
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    pathParameters(
                        getCertificateIdPathParameter(),
                        parameterWithName("versionId").description("Version Id")
                    )
                )
            ).andReturn()

        assertThat(spyCertificatesHandler.handleDeleteVersionRequest__calledWith_certificateId).isEqualTo(certificateId.toString())
        assertThat(spyCertificatesHandler.handleDeleteVersionRequest__calledWith_versionId).isEqualTo(versionId.toString())

        // language=json
        val expectedResponseBody =
            """
            {
              "type": "${CredentialType.CERTIFICATE.type.toLowerCase()}",
              "version_created_at": "${credentialViewResponse.versionCreatedAt}",
              "id": "$certificateId",
              "name": "$name",
              "transitional": true,
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

    private fun getCertificateIdPathParameter(): ParameterDescriptor {
        return parameterWithName("certificateId").description("The certificate identifier.")
    }
}
