package org.cloudfoundry.credhub.utils

import org.springframework.test.context.support.DefaultActiveProfilesResolver

class DatabaseProfileResolver : DefaultActiveProfilesResolver() {

    override fun resolve(testClass: Class<*>): Array<String> {
        return arrayOf(System.getProperty(SpringUtilities.activeProfilesString)).plus(super.resolve(testClass))
    }
}
