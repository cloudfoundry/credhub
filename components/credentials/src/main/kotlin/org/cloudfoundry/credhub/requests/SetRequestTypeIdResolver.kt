package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonTypeInfo
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData
import org.cloudfoundry.credhub.entity.JsonCredentialVersionData
import org.cloudfoundry.credhub.entity.PasswordCredentialVersionData
import org.cloudfoundry.credhub.entity.RsaCredentialVersionData
import org.cloudfoundry.credhub.entity.SshCredentialVersionData
import org.cloudfoundry.credhub.entity.UserCredentialVersionData
import org.cloudfoundry.credhub.entity.ValueCredentialVersionData
import tools.jackson.databind.DatabindContext
import tools.jackson.databind.JavaType
import tools.jackson.databind.exc.InvalidTypeIdException
import tools.jackson.databind.jsontype.TypeIdResolver

class SetRequestTypeIdResolver : TypeIdResolver {
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
        val subType: Class<*>
        val lowerCaseId = id.lowercase()

        when (lowerCaseId) {
            CertificateCredentialVersionData.CREDENTIAL_TYPE -> subType = CertificateSetRequest::class.java
            ValueCredentialVersionData.CREDENTIAL_TYPE -> subType = ValueSetRequest::class.java
            JsonCredentialVersionData.CREDENTIAL_TYPE -> subType = JsonSetRequest::class.java
            PasswordCredentialVersionData.CREDENTIAL_TYPE -> subType = PasswordSetRequest::class.java
            RsaCredentialVersionData.CREDENTIAL_TYPE -> subType = RsaSetRequest::class.java
            SshCredentialVersionData.CREDENTIAL_TYPE -> subType = SshSetRequest::class.java
            UserCredentialVersionData.CREDENTIAL_TYPE -> subType = UserSetRequest::class.java
            else -> {
                val message = String.format("Could not resolve type id '%s' into a subtype of %s", lowerCaseId, baseType)
                throw InvalidTypeIdException(null, message, baseType, lowerCaseId)
            }
        }

        return context.constructSpecializedType(baseType!!, subType)
    }

    override fun getDescForKnownTypeIds(): String? = null

    override fun getMechanism(): JsonTypeInfo.Id = JsonTypeInfo.Id.CUSTOM
}
