package org.cloudfoundry.credhub.controllers.v1.credentials

import org.cloudfoundry.credhub.generate.SetHandler
import org.cloudfoundry.credhub.requests.BaseCredentialSetRequest
import org.cloudfoundry.credhub.views.CredentialView

class SpySetHandler : SetHandler {
    lateinit var handle__calledWith_setRequest: BaseCredentialSetRequest<*>
    lateinit var handle__returns_credentialView: CredentialView
    override fun handle(setRequest: BaseCredentialSetRequest<*>): CredentialView {
        handle__calledWith_setRequest = setRequest
        return handle__returns_credentialView
    }
}
