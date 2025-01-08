package org.cloudfoundry.credhub.utils

class SpringUtilities {
    private constructor()

    companion object {
        const val ACTIVE_PROFILE_STRING = "spring.profiles.active"
        const val UNIT_TEST_POSTGRES_PROFILE = "unit-test-postgres"
    }
}
