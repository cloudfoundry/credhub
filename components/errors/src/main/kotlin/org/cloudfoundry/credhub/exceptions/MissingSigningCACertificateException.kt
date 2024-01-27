package org.cloudfoundry.credhub.exceptions

import org.cloudfoundry.credhub.ErrorMessages

class MissingSigningCACertificateException @JvmOverloads
    constructor(messageCode: String = ErrorMessages.MISSING_SIGNING_CA, parameters: Array<Any> = arrayOf())
    : ParameterizedValidationException(messageCode) {
}
