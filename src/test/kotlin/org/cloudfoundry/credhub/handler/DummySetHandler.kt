package org.cloudfoundry.credhub.handler

import org.cloudfoundry.credhub.request.BaseCredentialSetRequest
import org.cloudfoundry.credhub.view.CredentialView

class DummySetHandler : SetHandler {
    override fun handle(setRequest: BaseCredentialSetRequest<*>): CredentialView {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }
}
