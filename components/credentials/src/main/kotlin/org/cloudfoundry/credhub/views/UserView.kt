package org.cloudfoundry.credhub.views

import org.cloudfoundry.credhub.credential.UserCredentialValue
import org.cloudfoundry.credhub.domain.UserCredentialVersion

class UserView(
    userCredential: UserCredentialVersion,
) : CredentialView(
        userCredential.versionCreatedAt,
        userCredential.uuid,
        userCredential.name,
        userCredential.getCredentialType(),
        userCredential.metadata,
        UserCredentialValue(userCredential.username, userCredential.password, userCredential.salt),
    )
