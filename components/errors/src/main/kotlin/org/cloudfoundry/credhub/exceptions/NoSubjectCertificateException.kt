package org.cloudfoundry.credhub.exceptions

import org.cloudfoundry.credhub.ErrorMessages

class NoSubjectCertificateException @JvmOverloads
constructor(messageCode: String = ErrorMessages.MISSING_CERTIFICATE_PARAMETERS, parameters: Array<Any> = arrayOf()) :
    ParameterizedValidationException(messageCode)
