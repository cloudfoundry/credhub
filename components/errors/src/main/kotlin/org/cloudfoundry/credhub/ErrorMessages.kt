package org.cloudfoundry.credhub

object ErrorMessages {
    const val READ_ONLY_MODE = "Service Unavailable. Credhub is currently in read only mode."
    const val RESOURCE_NOT_FOUND = "The request could not be completed because the credential does not exist or you do not have sufficient authorization."
    const val TOO_MANY_TRANSITIONAL_VERSIONS = "The maximum number of transitional versions for a given CA is 1."
    const val TYPE_MISMATCH = "The credential type cannot be modified. Please delete the credential if you wish to create it with a different type."
    const val UNREADABLE_CERTIFICATE = "Unable to parse the certificate."

    const val BAD_REQUEST = "The request could not be fulfilled because the request path or body did not meet expectation. Please check the documentation for required formatting and retry your request."
    const val CA_AND_SELF_SIGN = "The parameters ''ca'' and ''self-sign'' cannot be used in combination. Please update and retry your request."
    const val CA_MISSING_PRIVATE_KEY = "The specified CA object does not have an associated private key."
    const val CANNOT_GENERATE_TYPE = "Credentials of this type cannot be generated. Please adjust the credential type and retry your request."
    const val CANNOT_REGENERATE_NON_GENERATED_CERTIFICATE = "The credential could not be regenerated because the certificate was statically set and is not self-signed or is invalid."
    const val CANNOT_REGENERATE_NON_GENERATED_PASSWORD = "The password could not be regenerated because the value was statically set. Only generated passwords may be regenerated."
    const val CANNOT_REGENERATE_NON_GENERATED_USER = "The user could not be regenerated because the value was statically set. Only generated users may be regenerated."
    const val CANT_USE_VERSIONS_AND_CURRENT = "The query parameters current and versions cannot be provided in the same request."
    const val CERT_NOT_CA = "The requested certificate cannot be signed by the given CA because the given CA is not a certificate authority. A certificate must contain the extension ''Certificate Authority: YES'' to be used to sign other certificates."
    const val CERTIFICATE_WAS_NOT_SIGNED_BY_CA = "The provided certificate was not signed by the CA specified in the ''ca'' property."
    const val CERTIFICATE_WAS_NOT_SIGNED_BY_CA_NAME = "The provided certificate was not signed by the CA specified in the ''ca_name'' property."

    const val EXCEEDS_MAXIMUM_SIZE = "Value exceeds the maximum size."
    const val EXCLUDES_ALL_CHARSETS = "The combination of parameters in the request is not allowed. Please validate your input and retry your request."
    const val INSUFFICIENT_HEX_ALPHA = "Password must contain at least 1 characters from A-F."
    const val INTERNAL_SERVER_ERROR = "An application error occurred. Please contact your CredHub administrator."
    const val INVALID_ALTERNATE_NAME = "A provided alternative name is not a valid hostname or IP address. Please update this value and retry your request."
    const val INVALID_CA_VALUE = "The provided CA value is not a valid X509 certificate authority."
    const val INVALID_CERTIFICATE_LENGTH = "The provided certificate value is too long. Certificate lengths must be less than 7000 characters."
    const val INVALID_CERTIFICATE_VALUE = "The provided certificate value is not a valid X509 certificate."
    const val INVALID_CONTENT_TYPE = "The provided content type is not supported"
    const val INVALID_DURATION = "Invalid duration specified. The supported duration values are whole numbers between 1-3650."
    const val INVALID_EXTENDED_KEY_USAGE = "The provided extended key usage ''{0}'' is not supported. Valid values include ''client_auth'', ''server_auth'', ''code_signing'', ''email_protection'' and ''timestamping''."
    const val INVALID_JSON_KEY = "The request includes an unrecognized parameter ''{0}''. Please update or remove this parameter and retry your request."
    const val INVALID_KEY_FORMAT = "The provided key format is not supported. Keys must be PEM-encoded PKCS#1 keys."
    const val INVALID_KEY_LENGTH = "The provided key length is not supported. Valid values include ''2048'', ''3072'' and ''4096''."
    const val INVALID_KEY_USAGE = "The provided key usage ''{0}'' is not supported. Valid values include ''digital_signature'', ''non_repudiation'', ''key_encipherment'', ''data_encipherment'', ''key_agreement'', ''key_cert_sign'', ''crl_sign'', ''encipher_only'' and ''decipher_only''."
    const val INVALID_MODE = "The request does not include a valid mode. Valid values for generate include ''overwrite'', ''no-overwrite'' and ''converge''."
    const val INVALID_QUERY_PARAMETER = "The query parameter {0} was not valid for this request."
    const val INVALID_REMOTE_ADDRESS = "The request was send from an invalid IP address."
    const val INVALID_TOKEN_SIGNATURE = "The request token signature could not be verified. Please validate that your request token was issued by the UAA server authorized by CredHub."
    const val INVALID_TYPE_WITH_GENERATE_PROMPT = "The request does not include a valid type. Valid values for generate include ''password'', ''user'', ''certificate'', ''ssh'' and ''rsa''."
    const val INVALID_TYPE_WITH_REGENERATE_PROMPT = "The request does not include a valid type. Valid values for regenerate include ''password'', ''user'', ''certificate'', ''ssh'' and ''rsa''."
    const val INVALID_TYPE_WITH_SET_PROMPT = "The request does not include a valid type. Valid values include ''value'', ''json'', ''password'', ''user'', ''certificate'', ''ssh'' and ''rsa''."
    const val MALFORMED_PRIVATE_KEY = "Private key is malformed."
    const val MALFORMED_TOKEN = "The request token is malformed. Please validate that your request token was issued by the UAA server authorized by CredHub."
    const val MISMATCHED_CERTIFICATE_AND_PRIVATE_KEY = "The provided certificate does not match the private key."
    const val MISSING_CERTIFICATE = "You must provide a certificate."
    const val MISSING_CERTIFICATE_CREDENTIALS = "At least one certificate attribute must be set. Please validate your input and retry your request."
    const val MISSING_CERTIFICATE_PARAMETERS = "At least one subject value, such as common name or organization, must be defined to generate the certificate. Please update and retry your request."
    const val MISSING_ENCRYPTION_KEY = "The credential could not be accessed with the provided encryption keys. You must update your deployment configuration to continue."
    const val MISSING_NAME = "A credential name must be provided. Please validate your input and retry your request."
    const val MISSING_PASSWORD = "A password value must be specified for the credential. Please validate and retry your request."
    const val MISSING_QUERY_PARAMETER = "The query parameter {0} is required for this request."
    const val MISSING_RSA_SSH_PARAMETERS = "At least one key value must be set. Please validate your input and retry your request."
    const val MISSING_SIGNED_BY = "You must specify a signing CA. Please update and retry your request."
    const val MISSING_SIGNING_CA = "You must specify a signing CA or indicate self-signing when generating a certificate. Please update and retry your request."
    const val MISSING_VALUE = "A non-empty value must be specified for the credential. Please validate and retry your request."
    const val MIXED_CA_NAME_AND_CA = "Only one of the values ''ca_name'' and ''ca'' may be provided. Please update and retry your request."
    const val NAME_HAS_TOO_MANY_CHARACTERS = "The request could not be completed. The credential name cannot exceed 1024 characters"
    const val NO_CERTIFICATE_PARAMETERS = "This request must include a value for ''parameters''."
    const val NOT_A_CA_NAME = "The name given for the CA does not reference a CA type credential."
    const val OVERWRITE_AND_MODE_BOTH_PROVIDED = "The parameters overwrite and mode cannot be combined. Please update and retry your request."

    object Oauth {
        const val INVALID_ISSUER = "The request token identity zone does not match the UAA server authorized by CredHub. Please validate that your request token was issued by the UAA server authorized by CredHub and retry your request."
    }

    object Interpolation {
        const val INVALID_TYPE = "The credential ''{0}'' is not the expected type. A credhub-ref credential must be of type ''JSON''."
    }

    object Permissions {
        const val ALREADY_EXISTS = "A permission entry for this actor and path already exists. Please use PUT to update the permission entry."
        const val DOES_NOT_EXIST = "The request includes a permission that does not exist."
        const val INVALID_ACCESS = "The request could not be completed because the permission does not exist or you do not have sufficient authorization."
        const val INVALID_OPERATION = "The provided operation is not supported. Valid values include read, write, delete, read_acl, and write_acl."
        const val INVALID_UPDATE_OPERATION = "Modification of access control for the authenticated user is not allowed. Please contact an administrator."
        const val MISSING_ACES = "At least one access control entry must be provided. Please validate your input and retry your request."
        const val MISSING_ACTOR = "You must specify an actor. Please validate your input and retry your request."
        const val MISSING_OPERATIONS = "At least one operation must be provided. Please validate your input and retry your request."
        const val MISSING_PATH = "You must specify a path. Please validate your input and retry your request."
        const val WRONG_PATH_AND_ACTOR = "The permission guid does not match the provided actor and path."
        const val INVALID_CHARACTER_IN_PATH = "Credential paths may only include alpha, numeric, hyphen, underscore, and forward-slash characters. Please update and retry your request."
        const val INVALID_SLASH_IN_PATH = "A credential path cannot end with a ''/'' character or contain ''//''. Credential paths should be in the form of /[path]/[name] or [path]/[name]. Please update and retry your request."
    }

    object Auth {
        const val INVALID_MTLS_IDENTITY = "The provided authentication mechanism does not provide a valid identity. Please contact your system administrator."
        const val MTLS_NOT_CLIENT_AUTH = "The provided certificate is not authorized to be used for client authentication."
    }

    object Credential {
        const val CANNOT_DELETE_LAST_VERSION = "The minimum number of versions for a Certificate is 1."
        const val INVALID_ACCESS = "The request could not be completed because the credential does not exist or you do not have sufficient authorization."
        const val INVALID_CERTIFICATE_PARAMETER = "The request could not be completed because the {0} is too long. The max length for {0} is {1} characters."
        const val INVALID_CHARACTER_IN_NAME = "Credential names may only include alpha, numeric, hyphen, underscore, and forward-slash characters. Please update and retry your request."
        const val INVALID_SLASH_IN_NAME = "A credential name cannot end with a ''/'' character or contain ''//''. Credential names should be in the form of /[path]/[name] or [path]/[name]. Please update and retry your request."
        const val MISMATCHED_CREDENTIAL_AND_VERSION = "The request could not be completed because the specified version does not exist or does not belong to the specified credential."
    }
}
