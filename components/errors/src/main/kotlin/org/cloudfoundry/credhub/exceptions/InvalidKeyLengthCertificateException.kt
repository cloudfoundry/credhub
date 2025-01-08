package org.cloudfoundry.credhub.exceptions

import org.cloudfoundry.credhub.ErrorMessages

class InvalidKeyLengthCertificateException
    @JvmOverloads
    constructor(
        messageCode: String = ErrorMessages.INVALID_KEY_LENGTH,
        parameters: Array<Any> = arrayOf(),
    ) : ParameterizedValidationException(messageCode)
