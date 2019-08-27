package org.cloudfoundry.credhub.controllers.v1.versions

import org.cloudfoundry.credhub.utils.VersionProvider

class StubVersionProvider : VersionProvider {

    override fun currentVersion(): String {
        return "x.x.x"
    }
}