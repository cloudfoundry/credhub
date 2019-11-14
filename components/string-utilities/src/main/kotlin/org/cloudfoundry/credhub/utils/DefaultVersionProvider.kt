package org.cloudfoundry.credhub.utils

import java.io.IOException
import org.springframework.stereotype.Component

@Component
class DefaultVersionProvider(resources: ResourceReader) : VersionProvider {
    final var version: String = try {
        resources.readFileToString("version").trim { it <= ' ' }
    } catch (e: IOException) {
        "0.0.0"
    } catch (e: IllegalArgumentException) {
        "0.0.0"
    }

    override fun currentVersion(): String {
        return version
    }
}
