package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonTypeInfo
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData
import org.cloudfoundry.credhub.entity.PasswordCredentialVersionData
import org.cloudfoundry.credhub.entity.RsaCredentialVersionData
import org.cloudfoundry.credhub.entity.SshCredentialVersionData
import org.cloudfoundry.credhub.entity.UserCredentialVersionData
import tools.jackson.databind.DatabindContext
import tools.jackson.databind.JavaType
import tools.jackson.databind.jsontype.TypeIdResolver

class GenerateRequestTypeIdResolver : TypeIdResolver {
    private var baseType: JavaType? = null

    override fun init(baseType: JavaType) {
        this.baseType = baseType
    }

    override fun idFromValue(
        ctxt: DatabindContext,
        value: Any,
    ): String? = null

    override fun idFromValueAndType(
        ctxt: DatabindContext,
        value: Any,
        suggestedType: Class<*>,
    ): String? = null

    override fun idFromBaseType(ctxt: DatabindContext): String? = null

    override fun typeFromId(
        context: DatabindContext,
        id: String,
    ): JavaType {
        var subType: Class<*> = DefaultCredentialGenerateRequest::class.java

        when (id.lowercase()) {
            CertificateCredentialVersionData.CREDENTIAL_TYPE -> subType = CertificateGenerateRequest::class.java
            PasswordCredentialVersionData.CREDENTIAL_TYPE -> subType = PasswordGenerateRequest::class.java
            RsaCredentialVersionData.CREDENTIAL_TYPE -> subType = RsaGenerateRequest::class.java
            SshCredentialVersionData.CREDENTIAL_TYPE -> subType = SshGenerateRequest::class.java
            UserCredentialVersionData.CREDENTIAL_TYPE -> subType = UserGenerateRequest::class.java
            else -> {
            }
        }

        return context.constructSpecializedType(baseType!!, subType)
    }

    override fun getDescForKnownTypeIds(): String? = null

    override fun getMechanism(): JsonTypeInfo.Id = JsonTypeInfo.Id.CUSTOM
}
