package org.cloudfoundry.credhub.handler

import org.cloudfoundry.credhub.request.BaseCredentialSetRequest
import org.cloudfoundry.credhub.view.CredentialView

interface SetHandler {
    fun handle(setRequest: BaseCredentialSetRequest<*>): CredentialView
}
