package org.cloudfoundry.credhub.utils

import org.springframework.test.context.support.DefaultActiveProfilesResolver

class DatabaseProfileResolver : DefaultActiveProfilesResolver() {
    override fun resolve(testClass: Class<*>): Array<String> =
        arrayOf(System.getProperty(SpringUtilities.ACTIVE_PROFILE_STRING)).plus(super.resolve(testClass))
}
