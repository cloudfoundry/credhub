package org.cloudfoundry.credhub.generate

import org.cloudfoundry.credhub.requests.BaseCredentialSetRequest
import org.cloudfoundry.credhub.views.CredentialView

interface SetHandler {
    fun handle(setRequest: BaseCredentialSetRequest<*>): CredentialView
}
