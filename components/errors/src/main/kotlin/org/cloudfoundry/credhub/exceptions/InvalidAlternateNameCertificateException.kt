package org.cloudfoundry.credhub.exceptions

import org.cloudfoundry.credhub.ErrorMessages

class InvalidAlternateNameCertificateException @JvmOverloads
constructor(messageCode: String = ErrorMessages.INVALID_ALTERNATE_NAME, parameters: Array<Any> = arrayOf()) :
    ParameterizedValidationException(messageCode)
