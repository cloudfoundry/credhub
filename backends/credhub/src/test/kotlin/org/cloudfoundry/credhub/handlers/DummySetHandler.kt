package org.cloudfoundry.credhub.handlers

import org.cloudfoundry.credhub.requests.BaseCredentialSetRequest
import org.cloudfoundry.credhub.views.CredentialView

class DummySetHandler : SetHandler {
    override fun handle(setRequest: BaseCredentialSetRequest<*>): CredentialView {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }
}
