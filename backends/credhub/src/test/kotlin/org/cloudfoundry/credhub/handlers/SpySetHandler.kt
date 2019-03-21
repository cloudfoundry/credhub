package org.cloudfoundry.credhub.handlers

import org.cloudfoundry.credhub.requests.BaseCredentialSetRequest
import org.cloudfoundry.credhub.views.CredentialView

class SpySetHandler : SetHandler {
    lateinit var handle_calledWithSetRequest : BaseCredentialSetRequest<*>
    lateinit var handle_returnsCredentialView : CredentialView
    override fun handle(setRequest: BaseCredentialSetRequest<*>): CredentialView {
        handle_calledWithSetRequest = setRequest
        return handle_returnsCredentialView
    }
}
