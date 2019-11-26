package org.cloudfoundry.credhub.requests

class CredentialRegenerateRequest : BaseCredentialRequest() {

    override val generationParameters: GenerationParameters?
        get() = null

    fun setRegenerate(regenerate: Boolean) {}
}
