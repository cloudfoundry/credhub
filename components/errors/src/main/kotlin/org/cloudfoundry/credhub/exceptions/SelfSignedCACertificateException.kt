package org.cloudfoundry.credhub.exceptions

import org.cloudfoundry.credhub.ErrorMessages

class SelfSignedCACertificateException @JvmOverloads
    constructor(messageCode: String = ErrorMessages.CA_AND_SELF_SIGN, parameters: Array<Any> = arrayOf())
    : ParameterizedValidationException(messageCode) {
}
