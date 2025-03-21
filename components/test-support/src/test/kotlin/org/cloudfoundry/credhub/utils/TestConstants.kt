package org.cloudfoundry.credhub.utils

class TestConstants {
    private constructor()

    companion object {
        const val INVALID_PRIVATE_KEY_NO_HEADERS: String = "some-invalid-private-key"

        const val INVALID_PRIVATE_KEY_WITH_HEADERS: String =
            "-----BEGIN RSA PRIVATE KEY----- fake\n" +
                "MIIEpQIBAAKCAQEAwqIrV8HpCuPyuJ6VvyG7gVhYJGAOX4zhclxkTAKT5rkE4Lfj\n" +
                "048GZsDghK+pHs+tVotfyrJzYGJoEBTn9Wy7kP5pQmLRF54imDztep15OlyoJmLZ\n" +
                "fRgct/8Kyxkjgg3PKVw68IiNhnTlYaw4CAyZ/13mvw2cWIYlag9LV5R2ifcyubaY\n" +
                "llxJhdWSXrcbYxrts1kRsUQTo99jJzKu71meLigMryaMry8xvjv1X8Yjq3s3Lud6\n" +
                "gWZ6BuaaaVVIjI9clGgR1MkgKJgVkWjNzDRiCxYnq1LHCho9bgKgiY4p604zPk9M\n" +
                "w4FhtCbOim6HOsHTimONZXfDNmfsJ9wJefA0UwIDAQABAoIBAEwsTcxFvuAdQFRS\n" +
                "9IZePFUt7yklUtrAd0dbs4EwDRRiWu9b6NVWh4nVeMlVOlotq0hQucfJuXACc3m/\n" +
                "xNx/lpTzjNyHcg/NOvrb9ZFkahqWQtTrIPVdZ3f3YBEGoKf4oZgtWX/j4Ye63j8w\n" +
                "uKklzWttI66oNAVNUv1ESRdYql/p5/BVSJaVK4bdkXqYHX2j3PrPd30ICwxz0bGd\n" +
                "41UdMiKMJhlkhIESsB8bcdRAEaMS2OaFKmBYIQF4RuY3syvFizJDtp/QEYfjy9tT\n" +
                "Xokd3Wzs6dncn/yyfvT0+yCDjYsNAgFvBmfHNBorywxILdtgJHuc9oO2EOeg58VK\n" +
                "Vt4eugECgYEA/wxb29pVamwxF71gKx/msBa5kwxV5N7NhTLdYyHwhQVErQlwn7Dg\n" +
                "J8qLfZqmn231yoGpKLZsu2mxdRvpd9nvOiW+ZF+fsrS8SEs5dMEqhojALm8rur+Y\n" +
                "5M0/Sk/A0lCbSmV+X7vmqaGzyNdgH7tYVIxXjAo4sEYN6GevjUB1JQECgYEAw1wZ\n" +
                "BhhsIvW9gfbuCdiTGlezUuIO3oxjvSSTNUaGAB7GUqB26toBnXi6oQi5iGu/dCYU\n" +
                "3CILOkV7kTX//2njOfWLp/kP+5nVKDgHoA/0gL609sgrdgkQ0KdZ3iuurimeqvDm\n" +
                "U5hpPrNcwz7yPJ/M081ve84pHq3wzVKpi1dMNVMCgYEA4e5JxTTg63hR+MyqTylg\n" +
                "SmanF2sa/7aa6r6HPRTIop1rG7m8Cco+lyEmdiq0JZDb5fr8JXOMWGylZa9HHwNw\n" +
                "ltrukK3gowbVr1jr2dBv4mNrkvaqDzFAuJZU1XhWwDfliH7l9tpV17jFsUmQ/isQ\n" +
                "cT0tJIG9e/Fiyphm+8K4wwECgYEAwXbCHUQwSoq7aiokX0HHo624G1tcyE2VNCk1\n" +
                "UuwNJa9UTV01hqvwL4bwoyqluZCin55ayAk6vzEyBoLIiqLM8IfXDrhaeJpF+jdK\n" +
                "bdt/EcRKJ53hVFnz+f3QxHDT4wu6YqSAI8bqarprIbuDXkAOMq3eOmfWVtiAgITc\n" +
                "++2uvZsCgYEAmpN2RfHxO3huEWFoE7LTy9WTv4DDHI+g8PeCUpP2pN/UmczInyQ4\n" +
                "OlKeNTSxn9AkyYx9PJ8i1TIx6GyFIX4pkJczLEu+XINm82MKSBGuRL1EUvkVddx3\n" +
                "6clZk5BLDXjmCtCr5DGZ01EbT0wsbsBM1GtoCS4+vUQkJVHb0r6/ZdXX=\n" +
                "-----END RSA PRIVATE KEY-----"

        // generate with ./build/credhub n -t ssh -n foo -k 4096
        const val SSH_PUBLIC_KEY_4096: String = (
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDs8lQIdJ+tnc9jufX9wLzCPVS1utoTJ" +
                "wzQO2NS5F07OEWXnR94XtYY3KtBLu10LHjZzH5maxdWYkyb4GgYSwV+6ln+Txn7" +
                "9LQT8gStbK+mJBFWnGplHNU+loHdHkKckOVihBgDfjsW58s46X9HmKAiUetXBaz" +
                "QX2pVOhOKBETgEstVKB1CoN0fP98mbergW+THHxDpbtodep1EoWZePn/Qe/jly7" +
                "joL8HZuVAwzunmBsrrm0B1cRF3mG4/XZDdHqbz1humoz/8V8KMBuC899XhN1yZv" +
                "mdZqe3OhpENr8O3e26p7xxTyCyOs5kk2Myv7YqWOyr43obFIzGUcLLMj3p1SDuk" +
                "gzpxCHPmiZ72zO/hZ+HkB6319iZPsZgrR8vapQsJY5MfYJO9KPj0BKlFdi9y578" +
                "VCj1pw6OYz7fuRrSfu/W0S1l9FLI450aFsNSji5ZX7elJ5A0qDQaFblECAsmbMj" +
                "T9MCDyJDjZfmtb9UY4j/ywFeYP26RLqbdWMZBYgukVg+isCyxJczecaJKRWBnUr" +
                "yz5sSvbsOC38rdu7LAl/vxf8m2ZY6d/TZ2SgTEDgD4YxOG6WZEm2z2JGpgGtQcV" +
                "O4ulfSa/xqovvidLc/kTWR15dVts+r1Uv7Btaax7XqTKqBkrxjhbpXD2RVQAeZh" +
                "BOQ80pPbFtvUPN1pAdgc14w=="
        )

        const val SSH_PUBLIC_KEY_4096_WITH_COMMENT: String = (
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDs8lQIdJ+tnc9jufX9wLzCPVS1utoTJ" +
                "wzQO2NS5F07OEWXnR94XtYY3KtBLu10LHjZzH5maxdWYkyb4GgYSwV+6ln+Txn7" +
                "9LQT8gStbK+mJBFWnGplHNU+loHdHkKckOVihBgDfjsW58s46X9HmKAiUetXBaz" +
                "QX2pVOhOKBETgEstVKB1CoN0fP98mbergW+THHxDpbtodep1EoWZePn/Qe/jly7" +
                "joL8HZuVAwzunmBsrrm0B1cRF3mG4/XZDdHqbz1humoz/8V8KMBuC899XhN1yZv" +
                "mdZqe3OhpENr8O3e26p7xxTyCyOs5kk2Myv7YqWOyr43obFIzGUcLLMj3p1SDuk" +
                "gzpxCHPmiZ72zO/hZ+HkB6319iZPsZgrR8vapQsJY5MfYJO9KPj0BKlFdi9y578" +
                "VCj1pw6OYz7fuRrSfu/W0S1l9FLI450aFsNSji5ZX7elJ5A0qDQaFblECAsmbMj" +
                "T9MCDyJDjZfmtb9UY4j/ywFeYP26RLqbdWMZBYgukVg+isCyxJczecaJKRWBnUr" +
                "yz5sSvbsOC38rdu7LAl/vxf8m2ZY6d/TZ2SgTEDgD4YxOG6WZEm2z2JGpgGtQcV" +
                "O4ulfSa/xqovvidLc/kTWR15dVts+r1Uv7Btaax7XqTKqBkrxjhbpXD2RVQAeZh" +
                "BOQ80pPbFtvUPN1pAdgc14w== dan@foo"
        )

        const val RSA_PUBLIC_KEY_4096: String = (
            "-----BEGIN PUBLIC KEY-----\n" +
                "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA7PJUCHSfrZ3PY7n1/cC8\n" +
                "wj1UtbraEycM0DtjUuRdOzhFl50feF7WGNyrQS7tdCx42cx+ZmsXVmJMm+BoGEsF\n" +
                "fupZ/k8Z+/S0E/IErWyvpiQRVpxqZRzVPpaB3R5CnJDlYoQYA347FufLOOl/R5ig\n" +
                "IlHrVwWs0F9qVToTigRE4BLLVSgdQqDdHz/fJm3q4Fvkxx8Q6W7aHXqdRKFmXj5/\n" +
                "0Hv45cu46C/B2blQMM7p5gbK65tAdXERd5huP12Q3R6m89YbpqM//FfCjAbgvPfV\n" +
                "4Tdcmb5nWantzoaRDa/Dt3tuqe8cU8gsjrOZJNjMr+2Kljsq+N6GxSMxlHCyzI96\n" +
                "dUg7pIM6cQhz5ome9szv4Wfh5Aet9fYmT7GYK0fL2qULCWOTH2CTvSj49ASpRXYv\n" +
                "cue/FQo9acOjmM+37ka0n7v1tEtZfRSyOOdGhbDUo4uWV+3pSeQNKg0GhW5RAgLJ\n" +
                "mzI0/TAg8iQ42X5rW/VGOI/8sBXmD9ukS6m3VjGQWILpFYPorAssSXM3nGiSkVgZ\n" +
                "1K8s+bEr27Dgt/K3buywJf78X/JtmWOnf02dkoExA4A+GMThulmRJts9iRqYBrUH\n" +
                "FTuLpX0mv8aqL74nS3P5E1kdeXVbbPq9VL+wbWmse16kyqgZK8Y4W6Vw9kVUAHmY\n" +
                "QTkPNKT2xbb1DzdaQHYHNeMCAwEAAQ==\n" +
                "-----END PUBLIC KEY-----"
        )

        const val PRIVATE_KEY_4096: String = (
            "-----BEGIN RSA PRIVATE KEY----- fake\n" +
                "MIIJKAIBAAKCAgEA7PJUCHSfrZ3PY7n1/cC8wj1UtbraEycM0DtjUuRdOzhFl50f\n" +
                "eF7WGNyrQS7tdCx42cx+ZmsXVmJMm+BoGEsFfupZ/k8Z+/S0E/IErWyvpiQRVpxq\n" +
                "ZRzVPpaB3R5CnJDlYoQYA347FufLOOl/R5igIlHrVwWs0F9qVToTigRE4BLLVSgd\n" +
                "QqDdHz/fJm3q4Fvkxx8Q6W7aHXqdRKFmXj5/0Hv45cu46C/B2blQMM7p5gbK65tA\n" +
                "dXERd5huP12Q3R6m89YbpqM//FfCjAbgvPfV4Tdcmb5nWantzoaRDa/Dt3tuqe8c\n" +
                "U8gsjrOZJNjMr+2Kljsq+N6GxSMxlHCyzI96dUg7pIM6cQhz5ome9szv4Wfh5Aet\n" +
                "9fYmT7GYK0fL2qULCWOTH2CTvSj49ASpRXYvcue/FQo9acOjmM+37ka0n7v1tEtZ\n" +
                "fRSyOOdGhbDUo4uWV+3pSeQNKg0GhW5RAgLJmzI0/TAg8iQ42X5rW/VGOI/8sBXm\n" +
                "D9ukS6m3VjGQWILpFYPorAssSXM3nGiSkVgZ1K8s+bEr27Dgt/K3buywJf78X/Jt\n" +
                "mWOnf02dkoExA4A+GMThulmRJts9iRqYBrUHFTuLpX0mv8aqL74nS3P5E1kdeXVb\n" +
                "bPq9VL+wbWmse16kyqgZK8Y4W6Vw9kVUAHmYQTkPNKT2xbb1DzdaQHYHNeMCAwEA\n" +
                "AQKCAgBivQDDnUXFJZP8rMuTeLOwBbq9GCY0APvX8keLjVpEiUiGy5UHpg11ws8i\n" +
                "lJmi5b1elVa++zV4a/IcqsD2Dp01rBbgYLolQm2gOiQ02KvBghovi3LSu9cpA7MO\n" +
                "H8QGVmMgUIdpPTsGaoVHLBY8EZ/5bUWyt8yx8HDxHwhxZSIGdg6BZ/v5fetnUEh/\n" +
                "TSKpZ+HIEGwNuoHt8uCCbvenokfE60RnDiP5rZ0MS6rdC/xwPLhmwgV0ay+qNL0M\n" +
                "bsMlQda0ma5gHHtXfoK1s1AHrwdTmKxf7PZIaQWOIIlluK7IUQlmixu01h+rP7A7\n" +
                "qJRzY3ty6ykXGDP1BptsjiIUGF4goDsEYT9fm5LEOE4oNPFTpD3ZCxRGd/bbioxd\n" +
                "1AAhj6172mAmoDGKrAr9ktVMYZJWKL72NU6X12LSqigR3uDmk0k8LzKj+sh0vR5P\n" +
                "LaX6kw9swCgJuw7q2CKml2JvMUpqC/zpQK4ZJH/QCS+CWWDvEBaUrkC5KEl2qzkb\n" +
                "sQMBKt5I2PkTjg4YmUxEIzZr0jOWC1Ps+kMQyjGzBGKJMemIgtL+B4P1WB2chZ1f\n" +
                "rZuus3DixgqK9kXPbbtNjlGsCKp2p0Kbb7iEAoGXsZzC1kmZBXSi1G2p0JNVjUBg\n" +
                "UDLlmhB+AZXdSv13kxGvdunxHm9ncpF2HDv7dQIKuTxN5JPNIQKCAQEA9qblXfRo\n" +
                "ctjnYYaTh14mnRP/AGziiPeo5IpqOMcPXeoCBsoybicRvNVoKQt/tPgvpE9AzfPQ\n" +
                "tiMDOx/T6CrUQLuW3nNnMfSIpoXzjJzNzU6ZOaVdXv8HFJtgxpxrB8weTJaKOIqA\n" +
                "JHPL5fLprDbQnWdjAiw7pfzvDubPSfUFnJTYAB1iAJp8vcHKbyYoo7bHGlU1uHcN\n" +
                "qceRaGIwwDcnsRBPyt0RcW7mnD8U1+rF86wB1t1z4G6quJybUKuQHIJxRpbzIpYU\n" +
                "9ukB1aZqfk2RPCabp7pTPLP/4aFd587Q1aRvHWnRhY9eg1QvJDTALtorJEvvhiHI\n" +
                "vyy/ieaGEf872QKCAQEA9e1Eg6us9Ji67HSL9nVSRxs8U+a3VeKYw7feCgg/a/Ve\n" +
                "pzHKd3m1vNA8Lod9Iv9I290s7au7OuJfM/FcUJn6r7QhSIoKvHkJ8iu2FMvwlIxA\n" +
                "N5+Gume2zhJ6e1a27doKy2teYs/aOxQbcNeToRZgRSuTVe39mFX82o8R9JLZInB6\n" +
                "HUhGd/c3+FzagmhjJkQd9VZsFJo6u+C6MlEQ6ZyI+lSq1k/mTX6mksrlkhIZov8u\n" +
                "NKobruomnMz0hdILX9ueEppYTjErPhavjlw0Oia5hYE4y25ivmHDZf/JB3z8b1W7\n" +
                "53zDU1Nhp0jK35Ef2tntfhj/NowGY4LyfUxdtmlWGwKCAQAcGjnp8Y3w/+uk/ftT\n" +
                "IhQOM5gLSVyqNGWG3Ipru6pxjdb7RRBn4oWv2TTL8GZ1jQ2IkAsXLB9skSKuGts/\n" +
                "CZozYew3njh0xaLILlzoeXktWjY1DjVMPIxm+akWF/5N3iDZoxFOjeE5xgPGSF39\n" +
                "ZCVyubPbLIUDTYVDUmLtzz/7bi4KHU7sOK3bxPe2oEdjF9Epm+nKAa6J2JYlqYJa\n" +
                "dC5Oi0g8GeIB5Zva04khbLtvHvr6qzKnsJQ9AoLjtxhtVyNm4o4DM8xhsXynBhX+\n" +
                "HAJfMxrrClyvfua5o3QalELRBLIwTL01lXc0SWQxoN0AuZTOxuQciT7hIU0VfjFq\n" +
                "XYVJAoIBAEYBpN9Wn4WBdLSa+LzP6PwU5Ld9lfL87j/It4xjjKpOzwMJSXl5TCLT\n" +
                "pE4ag6TSxwrPi1qc6E964V8H9h97tcEOpergYO4GBq7Jgquo4nNm+WDcKJ4nqAJB\n" +
                "gFxb8vcCetAtYFEAmj73GlilBYF1vTHzlZ2AghA7ah9NWu8kXmtPWXO8f1LnLSem\n" +
                "Rw2YaaEbAuw0DdBPlyikcFyidw4JYXThZUBcvlKRGxnuaCuMu3+K5LxZMEg6n4ND\n" +
                "VNhDUrmW6wigp0Ka/JRQIOmFldh37ZfzkRdX9QP9EIKYrcFT8wg+f58GBRRTSBk2\n" +
                "v4mk5kyGfPTIaN4+PhNV03GXq5WhpsECggEBAMFMfqnqDWFVhkV7+cLYzcEmNXeb\n" +
                "1GqbszI7sDRHNt3yb1JIkNDAbwmX4aCPWgF0xIn0LVHaAg2nbGGZQKX4PE3+8A+h\n" +
                "2fogM0KlS3zn+qFuZJ3A8WETaD6zZcNff4wANz9NDZHUwYb4LAf6pptwlQexW1NH\n" +
                "w+u5e8YFE2iF3yCMP60GApTyR3RBNWa6I4yZ72s9p92Kcv5+bkR3srnw1eJsvHEE\n" +
                "lzD+HCQtoCJlCSDhur+osEsS+zpwclpPHsgAoyqfMlneu/H8Zssa0TUxLBDVx6fp\n" +
                "gVJz8k/YqVaXX3OmF2YLihmku7Stsqwifnpu/Io9gLL2wM8GyPonwfe3d1E=\n" +
                "-----END RSA PRIVATE KEY-----"
        )

        const val TEST_CA: String = (
            "-----BEGIN CERTIFICATE-----\n" +
                "MIIC/zCCAeegAwIBAgIUbW0U9/70rhPUj7qsG+kplvNKxfYwDQYJKoZIhvcNAQEL\n" +
                "BQAwDzENMAsGA1UEAxMEdGVzdDAeFw0xOTA5MDQxODI5NTRaFw0yMDA5MDMxODI5\n" +
                "NTRaMA8xDTALBgNVBAMTBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n" +
                "AoIBAQC43kce29qg4h46x4b6K7WVxR4EQTKaa9JS+sj8NN8FJRQJljxNDiWH/0kM\n" +
                "YwG2VYq/XGibDDaEiGqhJ4ozbWiZcwczddPLQlRuV7XIwsY0RW/iqt2CT5hf6QXC\n" +
                "jQX3XD3hcez0S1KpEcYMycLYkoNARGxcQz1mh7EuyzCLN+Uh47JK56eOlUN4iS2o\n" +
                "xz9HfB5NNORBZi8QSPZdZ6VrKOzaeQw7bO4jptyHJSmFGU9FiOa2OTj/kYnWggJH\n" +
                "gmSE4qh5e55Lgl4aCr/Cl31DIChxnIgMz0qiCyuV111sBnKq3kyFrEejMHshIYeU\n" +
                "kk+iAGoOCaIsxkbTkL8id+8uszJxAgMBAAGjUzBRMB0GA1UdDgQWBBRio//8/deq\n" +
                "M5Bw98SgEqfAy4btJjAfBgNVHSMEGDAWgBRio//8/deqM5Bw98SgEqfAy4btJjAP\n" +
                "BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCEHLDlselE4BZ+angg\n" +
                "00eHEJ2RU4BaIdfzYgcCwj7rfh2HeHFl4OphM3XWjzDFuEDFc7u2dhfaSZbkHJtc\n" +
                "zGCkKPRkYMHci6Aq2nbeIXahKRHwfycQWbOKE4aOooblY7dH8iTbzrHQY7TO3sJV\n" +
                "owt82sKm+FMdjWI0CkCsK55X+zT8WkNPxo6xLWSppaRcGYLYPFGuBcIVWuFyqCN/\n" +
                "T4DSBV+SDFTp0SOd9R4HydAmwksar+tdhJoCW+N1WkF02q83NLkVX7rlPrJ9DPy7\n" +
                "EpKeflegYY8nMLDjhH7m8p5niNO0caiNEzHrpTs5cqlFJZQF15Lu9u+6/sYWsRAW\n" +
                "IH3c\n" +
                "-----END CERTIFICATE-----"
        )

        const val TEST_TRUSTED_CA: String =
            "-----BEGIN CERTIFICATE-----\n" +
                "MIIDTTCCAjWgAwIBAgIULxxoB3zfye0MzzRQGtKtw8CC2p4wDQYJKoZIhvcNAQEL\n" +
                "BQAwGjEYMBYGA1UEAwwPZm9vX2NlcnRpZmljYXRlMB4XDTE3MTEyMTE2MjQ1NFoX\n" +
                "DTE4MTEyMTE2MjQ1NFowGjEYMBYGA1UEAwwPZm9vX2NlcnRpZmljYXRlMIIBIjAN\n" +
                "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvgmVFC08CaGlp2ENKc5mym9BkcEL\n" +
                "E2030VXTJJSiLH1Py3s79rbJL4F/loxAMSbQCuKIADZZ4Wu7Xp8bFY92u0nNrAuG\n" +
                "Xw1omhfF5UTi1vewRG8inxdJZs9vxsiXZWI6WzUpvJZeCMvvKlkhA/C+GwjpIdRg\n" +
                "3fVZ44JvdZOx4cDUagRkDRcsHABp/ip19xhfZGLwFuJw1wd5kxZmZKCreoel+b/5\n" +
                "BaQyFD0L9OkSfq1Y/nMqOdIbXEnpeg8sawhQan0s7G98MTsvDF14jnucCECLO1fg\n" +
                "1YpxoBTDkNlrIPq4G8UO4+GNz5FJEIBGOsiRmEn0VjFEpZ3k+t/Nkf/b6wIDAQAB\n" +
                "o4GKMIGHMB0GA1UdDgQWBBQ3ZlJJaG9Brzf3IM6tWsMJce6YIDBVBgNVHSMETjBM\n" +
                "gBQ3ZlJJaG9Brzf3IM6tWsMJce6YIKEepBwwGjEYMBYGA1UEAwwPZm9vX2NlcnRp\n" +
                "ZmljYXRlghQvHGgHfN/J7QzPNFAa0q3DwILanjAPBgNVHRMBAf8EBTADAQH/MA0G\n" +
                "CSqGSIb3DQEBCwUAA4IBAQAlbxUF4Eaz0tXSo7oM02Mt3YqhuP7XZpZE5KYpn5qE\n" +
                "utYzJdSJeMsfUpZcmv1pbZ4uepxgBxQKssKRmglzEMX2wxl9WyEPxKkyLTX+XCX9\n" +
                "Vd6IBi5Pft6v2u94bKlGZKigNojGfbzXDYuSU6SAud5GD77RM1vx/pPAa2eG8qSX\n" +
                "OcGQAtHrcSAvl58IqXAmci3akNKN4G5PxNoze5lQ25umQbHTlwvOMwFgPSXseYvm\n" +
                "/f98b+Q6lIdklw6g3XWUCmTkscRM+5mvb+1FKHWU8KiXN7CM+ONXjudO8Ixyyion\n" +
                "pBumFgiA2FQXUpunDCv38dccPb8y/EyhRSQyx+Trusted+\n" +
                "-----END CERTIFICATE-----"

        const val TEST_CERTIFICATE: String = (
            "-----BEGIN CERTIFICATE-----\n" +
                "MIIDCDCCAfCgAwIBAgIULKbJCRQZ251UjMFdqyrwfyWlh60wDQYJKoZIhvcNAQEL\n" +
                "BQAwDzENMAsGA1UEAxMEdGVzdDAeFw0xOTA5MDQxODMwMTFaFw0yMDA5MDMxODMw\n" +
                "MTFaMBsxGTAXBgNVBAMTEHRlc3QtY2VydGlmaWNhdGUwggEiMA0GCSqGSIb3DQEB\n" +
                "AQUAA4IBDwAwggEKAoIBAQC1rTHTp/PvMe0P3Pb76nAr/xrdXehrvgYldPzv7I2W\n" +
                "nR3JHMh5Sk9Xmra27Jd61e5257C3EKa8YpnAISRvPLUUqcFzvncQ6BYHIiLwdRpX\n" +
                "eNYh7OlqFQQ2/6SgeJ2OXWj3QqI9Ih3QVHYAnvMP4cGoVJNpvkotodE+jHfjFO2i\n" +
                "jmyVkKGqNSyy0YKvF0OcNjr2RVvG/jyFmMEzIqSJtJ1wZtEZITZ96ZaLdTD+6GgO\n" +
                "xuCHdl0nUPI+m//3hSon/f9YNO4FTfMjUAjuwh7r5fX+VdEypWcyn/flwfp91xZ6\n" +
                "lLtjJuJ+/ZcUH+Dcdwm1VEp9gVrJLWGDn5hdrN2Cay5HAgMBAAGjUDBOMB0GA1Ud\n" +
                "DgQWBBQ5g2Wq21t5ktgBaHKCXUokgFN5iDAfBgNVHSMEGDAWgBRio//8/deqM5Bw\n" +
                "98SgEqfAy4btJjAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCROXru\n" +
                "J3h8hKRsS4EvLpwyfEPp5A4sdY8mPzX0XGNTfnXnsNPvprDmwDdlTaejyMbK7vD+\n" +
                "V6R2XFr+D5XwkMqa4sWRJzPPj2tydCCb695Ozb2v5vWteiaUbIJEJuO4VU7paKPa\n" +
                "HltRvnI8BAv/8wdIm0xnm6hl7Gs3lGQs6ei1AonFnjvGEhg+/H7104qm903Pkcr6\n" +
                "XvHXp4cSK22OeendqVjpLAEnP3GOq5caGIiU8Q/sDbfVS+hh3eC+86fVpsWxn6rj\n" +
                "FSeZU/sNt18vDgxfPmlHsNOdmphwOneX95fAbE6Bj46b6uJg4wJ6yaRtsXspJtgk\n" +
                "7S/JfXIWVECjyaUE\n" +
                "-----END CERTIFICATE-----"
        )

        const val TEST_PRIVATE_KEY: String = (
            "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIIEogIBAAKCAQEAta0x06fz7zHtD9z2++pwK/8a3V3oa74GJXT87+yNlp0dyRzI\n" +
                "eUpPV5q2tuyXetXuduewtxCmvGKZwCEkbzy1FKnBc753EOgWByIi8HUaV3jWIezp\n" +
                "ahUENv+koHidjl1o90KiPSId0FR2AJ7zD+HBqFSTab5KLaHRPox34xTtoo5slZCh\n" +
                "qjUsstGCrxdDnDY69kVbxv48hZjBMyKkibSdcGbRGSE2femWi3Uw/uhoDsbgh3Zd\n" +
                "J1DyPpv/94UqJ/3/WDTuBU3zI1AI7sIe6+X1/lXRMqVnMp/35cH6fdcWepS7Yybi\n" +
                "fv2XFB/g3HcJtVRKfYFayS1hg5+YXazdgmsuRwIDAQABAoIBABkK3EZqQplNuXlT\n" +
                "97DhL5XGSU61kMG2j3mpoZVKIc40BBS3ufk2Fq+4V3KUNDaDYfvT6KujSPMeEvFv\n" +
                "4BTROmi0aZe/FlcnQU9kaN/aVHI1lCwC+xMF/e8S1/94AMfMn8O4Kfg2nq4b0P7k\n" +
                "P2mIsJK3wxtyq8jpzZegnISZsD6VcGimahRkNeU15/qVRYjVIH291RpfUkI2bp2V\n" +
                "fC8AwdnvS20K2KdL9rJIWKFTWRY1ziOdlNLd2EfYhFXbMyRgh5lBd1gl/pLaDihS\n" +
                "OmaEsgVaEADAFWU6LeCC7pNKdUKT2F+3VZflf1Hkz+8dx1LJ250zrROFQFcpneB8\n" +
                "E1zg3dECgYEA4KA3ymC1O5vNjdW22jFud/O0iwna95dtiFJ3gSjq+VnAjV4Q1yo5\n" +
                "WQgi3xzKS1pIw5CpS3A8cR2zJ39eMbWvUmfd8m9rUnN6dJLUedvJt2ho2jl2o5a5\n" +
                "/wX2B/O2y3uf8hoJjN6tK9COVyBF8j9KjE7Rzdd/Qhi7FWxUtGL5KKkCgYEAzw1F\n" +
                "CkErY//xs3ygk3y/Pdn3Z6nddCyd2ySfCOo/6S1HPrliX6AImYfE/TU3Sxa1D5hl\n" +
                "Df/kFEx/81Bs61QPhPDDVPnQ3gs+517fv3jbHe3R1bWX0eunnX3Tn+rQ4ep+LCIQ\n" +
                "I44b3SxiSKmjYxIj0l35cJwIOVhNxznfjBAlRW8CgYAoh6ApavOocr9PFT2t9vdY\n" +
                "u2dbIwcYX4FK9J5NdsWXAkPE/jEJsbuxPc+U9Evn9r1kVAjH7NNrEZHO0aN8Uqz0\n" +
                "sHsSkFoMAXwZ5phh+G9YIYWxwmaOs9aRllDDNI1J/99nPp10hoU2f6X/QHp+cD8S\n" +
                "O/KNMpHqqi2veuF5vtX4KQKBgHTc6oDVM6ZniYZi60cTe+VvJwLtjz7JB/fufYzM\n" +
                "mnIDyliOzgVnEDOHvBmmdaT+FgfNXgw+x/7lBrrQRAm3EmNYeQd3UPpiooh4thUe\n" +
                "I56K4oqayiwDtEFiCZYTNP6uGbTTLQTEatm0+WxFwyBh1rIftHBowQOM4al28sPd\n" +
                "QQwlAoGAQubX3mTUkJ5F1z/J6iVxUDKJtGRwLL8gr4pFN7HX37vdnlbAkh317Y4l\n" +
                "VxynZOICM9G6M1VyN9FjY7v4VyRv6kTnIhDHlVyCpQYnrccAtYkl3QoYbPPmVgZL\n" +
                "0jFnIGaLpUtFZYFbHuAlgv5XqwDBfi/qOQwBD3MVdqn2z5v4guI=\n" +
                "-----END RSA PRIVATE KEY-----"
        )

        const val TEST_PRIVATE_KEY_PKCS8: String = (
            "-----BEGIN PRIVATE KEY-----\n" +
                "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC1rTHTp/PvMe0P\n" +
                "3Pb76nAr/xrdXehrvgYldPzv7I2WnR3JHMh5Sk9Xmra27Jd61e5257C3EKa8YpnA\n" +
                "ISRvPLUUqcFzvncQ6BYHIiLwdRpXeNYh7OlqFQQ2/6SgeJ2OXWj3QqI9Ih3QVHYA\n" +
                "nvMP4cGoVJNpvkotodE+jHfjFO2ijmyVkKGqNSyy0YKvF0OcNjr2RVvG/jyFmMEz\n" +
                "IqSJtJ1wZtEZITZ96ZaLdTD+6GgOxuCHdl0nUPI+m//3hSon/f9YNO4FTfMjUAju\n" +
                "wh7r5fX+VdEypWcyn/flwfp91xZ6lLtjJuJ+/ZcUH+Dcdwm1VEp9gVrJLWGDn5hd\n" +
                "rN2Cay5HAgMBAAECggEAGQrcRmpCmU25eVP3sOEvlcZJTrWQwbaPeamhlUohzjQE\n" +
                "FLe5+TYWr7hXcpQ0NoNh+9Poq6NI8x4S8W/gFNE6aLRpl78WVydBT2Ro39pUcjWU\n" +
                "LAL7EwX97xLX/3gAx8yfw7gp+DaerhvQ/uQ/aYiwkrfDG3KryOnNl6CchJmwPpVw\n" +
                "aKZqFGQ15TXn+pVFiNUgfb3VGl9SQjZunZV8LwDB2e9LbQrYp0v2skhYoVNZFjXO\n" +
                "I52U0t3YR9iEVdszJGCHmUF3WCX+ktoOKFI6ZoSyBVoQAMAVZTot4ILuk0p1QpPY\n" +
                "X7dVl+V/UeTP7x3HUsnbnTOtE4VAVymd4HwTXODd0QKBgQDgoDfKYLU7m82N1bba\n" +
                "MW5387SLCdr3l22IUneBKOr5WcCNXhDXKjlZCCLfHMpLWkjDkKlLcDxxHbMnf14x\n" +
                "ta9SZ93yb2tSc3p0ktR528m3aGjaOXajlrn/BfYH87bLe5/yGgmM3q0r0I5XIEXy\n" +
                "P0qMTtHN139CGLsVbFS0YvkoqQKBgQDPDUUKQStj//GzfKCTfL892fdnqd10LJ3b\n" +
                "JJ8I6j/pLUc+uWJfoAiZh8T9NTdLFrUPmGUN/+QUTH/zUGzrVA+E8MNU+dDeCz7n\n" +
                "Xt+/eNsd7dHVtZfR66edfdOf6tDh6n4sIhAjjhvdLGJIqaNjEiPSXflwnAg5WE3H\n" +
                "Od+MECVFbwKBgCiHoClq86hyv08VPa3291i7Z1sjBxhfgUr0nk12xZcCQ8T+MQmx\n" +
                "u7E9z5T0S+f2vWRUCMfs02sRkc7Ro3xSrPSwexKQWgwBfBnmmGH4b1ghhbHCZo6z\n" +
                "1pGWUMM0jUn/32c+nXSGhTZ/pf9Aen5wPxI78o0ykeqqLa964Xm+1fgpAoGAdNzq\n" +
                "gNUzpmeJhmLrRxN75W8nAu2PPskH9+59jMyacgPKWI7OBWcQM4e8GaZ1pP4WB81e\n" +
                "DD7H/uUGutBECbcSY1h5B3dQ+mKiiHi2FR4jnoriiprKLAO0QWIJlhM0/q4ZtNMt\n" +
                "BMRq2bT5bEXDIGHWsh+0cGjBA4zhqXbyw91BDCUCgYBC5tfeZNSQnkXXP8nqJXFQ\n" +
                "Mom0ZHAsvyCvikU3sdffu92eVsCSHfXtjiVXHKdk4gIz0bozVXI30WNju/hXJG/q\n" +
                "ROciEMeVXIKlBietxwC1iSXdChhs8+ZWBkvSMWcgZoulS0VlgVse4CWC/lerAMF+\n" +
                "L+o5DAEPcxV2qfbPm/iC4g==\n" +
                "-----END PRIVATE KEY-----"
        )

        const val TEST_PRIVATE_KEY_EC: String =
            "-----BEGIN EC PRIVATE KEY----- fake\n" +
                "MHcCAQEEINZ8J4RQ62sqtAPjcXxDjGbXxw09K+9elaypfMlPwsNSoAoGCCqGSM49\n" +
                "AwEHoUQDQgAEvTOI8qakeZy8Y1K/yS8pgM9w1vJRBjWc8nz7E1ggm4RrMTyXzcZN\n" +
                "1S4D2k7uEFzZxn5eA6xMZIkh7NhT27mUkg==\n" +
                "-----END EC PRIVATE KEY-----"

        const val ENCRYPTED_TEST_PRIVATE_KEY_PKCS8: String = (
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
                "MIIE6TAbBgkqhkiG9w0BBQMwDgQI6XcyFAMjPKsCAggABIIEyJX2fDzS2EchDJ01\n" +
                "UtJ1NN7SFcOXzMtiBGvUjupuuinbiwbi+DEMBT1z/bfwrFBflvK9T3k1iKsV4B3Y\n" +
                "a81HpcqEpowiS0KjVHQzPY21ot1Otjk75JcsnYU3jHJxinU7agmaWcmweSX4uE1H\n" +
                "N7lGNH/BTgx/XndHc+XceQXUHcnw5I87W/YgQQBHjTN3ntqwoNGJAsYsGD6uUoCd\n" +
                "/a4LKFiZjVfs5FgoMT6D5CwteoOmjDKfT6ymhaHtvzCBm3myt3kT1Rr04rC5b2g1\n" +
                "m2whiO61vTJwqrn8PjXVwpY64sdEglWDhAPomI5IJXR+GY0xb6aVt8GIeHCqwsvd\n" +
                "9SPpfWItFHzS/IIFPWUQ4BgzE4jnWyl5bOVHWev2ch+rtlB3s4nItgewtfnYKIm2\n" +
                "vIMBGj9ACB8v7GpMOm94hzwoxZzJMzNO5J/dqY8s0Y+mm5e2ePMOe5mR7vMpBAAl\n" +
                "4DUVnznqfcte41Db+P4mQvyjAe7S5Ir/ScI4ZBcpc7PxOHDgWFeNjonwsAr10s7t\n" +
                "4OTmlTotlXSe64GC72OYkCo7HTD7tU9b4MvmGKK+YfaLeturRufddn9KfETOwYU3\n" +
                "nudnqr5A3P0ahAHDnMnFtd3GX4JuEsg+7OHp1iH4VzCmLSTpJI2PR80vhO4g1Nft\n" +
                "24DnO2XmppE0RkhlvuNQMAaqiOduZbdu+zqRG7qrH6UVtO9yrdYqimyl5s0BncLK\n" +
                "90iPLegUscAEUOg26xxn7dzXRqrkgKhVNcJuFQ9Rlqqgo4/3gG7oydmcZ0s57vXG\n" +
                "hjnJSxbjqkd6rbhuKyh1WIgmUz+h2HtxreqkVHd0gncjoywFzntzvIgb//mwAbei\n" +
                "6xbgSJuuU8PN2mryx/j9oAsxtBJ7auf2lS1lQaBRI7l4fUeQZI77NMzrWiB/spO8\n" +
                "4OFBm0VN+oBj0rRmjj3kRtq0AIF/6cu/RkvLWGufGu1S95Gwgk+FA//2X2T27M8g\n" +
                "OiPZQEE6Ymt9ixfzUHowAlWb2EfG/YBnHBrzypzWiukvYuuQAp3nCZ2uGUTj5thd\n" +
                "6unJrk6Z+ucfg46E2z7zXmTKlDUNM+6zYD1B66Tplr66A6Ra+Jq3sjeLbinDp1lF\n" +
                "4YmkUE62dO1Ns33bKIKU5g9qzVd+jzJsmViFksYm1/qTwXc285U/g+bLFqiiWJYp\n" +
                "E6J6C3a24GrwIsBgmh1RrwlU8FHNOSVJZSA2pdo5YsSzkhTZljGsgGbc0qERd/rf\n" +
                "86S8Y7/w0yiJKUscJrN9Y95kLV3ldQSpOvsECHEwXow4jQQ06ZgkLwNL+gcyXqkZ\n" +
                "IIEUM+TIXFwWq3gf1LgIA9Yjx11/0j7hI0KZWwNTd5xZA1rv53lJYiYtVtBCJ8ll\n" +
                "P86s3C8HNaIMrDmqTqwGpfrSZQdjYpNJ3QwhMuLNyk5td9oXF3DKoBc1CDmALTSB\n" +
                "ec/lfO3xM+/TlcTbi49fw0PUwUcJvlhXko4GkrSGGO3dSd7ZKHzK76ENK0hPaEW9\n" +
                "Jtn9+05pHqZz3RXxAkKc9iAYJdwNNE4++QDN3xlNSz4lN83UwpzoxK4jh4gngZp/\n" +
                "YW49Si94MZKwQPi9ZUClBoEcg5yHBrcGUfng6V4no3aK+4d8O29CuxM5SG3a8Qu8\n" +
                "0gYZxzCMuD8xe/suAw==\n" +
                "-----END ENCRYPTED PRIVATE KEY-----"
        )

        const val OTHER_TEST_CERTIFICATE: String =
            "-----BEGIN CERTIFICATE----- fake\n" +
                "MIIC5jCCAc4CCQDiRd5QC3sIpjANBgkqhkiG9w0BAQsFADA1MQswCQYDVQQGEwJ1\n" +
                "czELMAkGA1UECAwCbnkxCzAJBgNVBAcMAm55MQwwCgYDVQQDDANwaXYwHhcNMTkw\n" +
                "MzIwMTkzOTAzWhcNMTkwNDE5MTkzOTAzWjA1MQswCQYDVQQGEwJ1czELMAkGA1UE\n" +
                "CAwCbnkxCzAJBgNVBAcMAm55MQwwCgYDVQQDDANwaXYwggEiMA0GCSqGSIb3DQEB\n" +
                "AQUAA4IBDwAwggEKAoIBAQDmY9+PKJCe6Isk9hV4czDBE/iOu0Zi3rvwIK6dWbJq\n" +
                "j2z3lCJgmsLTG16r4kYXsKwjDfviBFhny0KtGfre+vizOeCHNf+RtIJ2W7bVmZoF\n" +
                "HGsv4niygmmYitlLRkVMBZ08SKEx7X6/TjsFFZYqt9GEVjwJEjSzDsb5HOEsFwgS\n" +
                "u9g7v07gQ2J2+AlsqLmM/IdpAJH1dHIha4wnxZaSlIyvKTMgs2RmOrFEEk1tuKqz\n" +
                "P7XdtWZC1DGxVPpNjyCHjVmcK9uI6nQU6S+FWObOngGYyaOw6nICgPCGmLUt7adK\n" +
                "MIZdYifjC0d4tJFIbKtHT9QcKOYu7EeAD6YVg6Xz8VHZAgMBAAEwDQYJKoZIhvcN\n" +
                "AQELBQADggEBAKT7jsM9LB8tvxRErm1vENAiO6rIkqcSO4+/cnaOISOELu8A0mdi\n" +
                "9AaI9hE60BNeJvZdLuyQKOyIC3+ky2WCza+J9ajoVR2GWDDz60j2YIArSjFhm5Bo\n" +
                "YfnFyvT59b/QRy4Uh4xlHXRPOGfg5vC99tk3omgyV9w37sUzKah/BkwLhtqkCVGF\n" +
                "HIkal0qkT084giO8S7pV0MO3ua+cmaSr8C1pRsRX91uFf8alNTjV3eeobeOb8xe7\n" +
                "ZW83Uc7T0H06XgTr4pH4ploR2hm8d36NlUPaYw4UMmCidYbNliuY35Zc8PUApJGV\n" +
                "PTH1yYdWl8KRAujeBsA+t+pXHH3WxZac4nY=\n" +
                "-----END CERTIFICATE-----"

        const val OTHER_TEST_PRIVATE_KEY: String =
            "-----BEGIN RSA PRIVATE KEY----- fake\n" +
                "MIIEpQIBAAKCAQEA5mPfjyiQnuiLJPYVeHMwwRP4jrtGYt678CCunVmyao9s95Qi\n" +
                "YJrC0xteq+JGF7CsIw374gRYZ8tCrRn63vr4sznghzX/kbSCdlu21ZmaBRxrL+J4\n" +
                "soJpmIrZS0ZFTAWdPEihMe1+v047BRWWKrfRhFY8CRI0sw7G+RzhLBcIErvYO79O\n" +
                "4ENidvgJbKi5jPyHaQCR9XRyIWuMJ8WWkpSMrykzILNkZjqxRBJNbbiqsz+13bVm\n" +
                "QtQxsVT6TY8gh41ZnCvbiOp0FOkvhVjmzp4BmMmjsOpyAoDwhpi1Le2nSjCGXWIn\n" +
                "4wtHeLSRSGyrR0/UHCjmLuxHgA+mFYOl8/FR2QIDAQABAoIBAQDLucUWcmhwHHHu\n" +
                "XSzfNf0GvwIsNK4o/4xw6nV97rM2R120D+nWQwPEaY9trskMac3Nsa/qTK1gGvz6\n" +
                "1N5iDsucsLE63yT/Uv+Kac9jUlA/9MFTto/ESk3V9fHv/lOIxe4kQJVJ8RkDUcoe\n" +
                "1NfVLna27wpnexHexFJuNntm4XbiGEtJhNyrkS9KyCygkojp+AAsY0nR6Rv+9Fua\n" +
                "n97DroAdSA0EbHky70E3efbb3obmpG1Fagu/Nq3Wv269qq+o6Ecz8Xtq3GLgb3w4\n" +
                "T4FxjRXOWsbtMRUxRD4+bfgGgZMFQ0JSmLPUlMcC0CBWO08NSf8o+DrYf+Ud+DGw\n" +
                "/N5uJQABAoGBAP4uSGZHEjaBg4X6SCssK1JK+q+vj5hJnUEUu+8M0FLpiUKaJvnD\n" +
                "l/DLaWJDLAk37devTziji/5Bz/SFQCfnqigwCRYUG0WcsWGWZDJ0BwXm1eDPoe8M\n" +
                "u1oSYfpSAWtyxqGXufsbU12b1O5Cc+FLBYbFkaXQclv8qidy5i5kudvZAoGBAOgK\n" +
                "ACPlduJUM/NdLVewHX8HP74iC/Ie+mvNppdkWOr7upxcvDTHxpFeh6LV7C1DJoY2\n" +
                "frLh2eI8km1pNA3iFCxZpnMPfdb7maOiAVAgSTQeBKFXxuAa1jMRNX/2qvRs31Q1\n" +
                "Eb3BUbscPcR/Rsuk0fN97S4zhstLAaBhGhO2N2YBAoGBAOEzfn/nvjI+o5oDuwdN\n" +
                "NgDOX7dis7X4mvQ7e5r73mNneG5jB99ItYjpoDAoVY7BV+A9+dGzzWfzRV1e5g21\n" +
                "CqRakuJV5CfUAbD1v0aYWFSZRavOKqoSvLe8C8Tt/UYGxggL1wKtHjqUw55pkCPv\n" +
                "BTF4QGgJ/BiWDueuvFQkeCtZAoGBAJ6Hjpb3w+RXkPK4+yyIp25NHpChJDY0UfTr\n" +
                "GOEf7twERfdkKDWLM6/HvLVUoDpAQYa6no9KXJkDtyrHEIhXqF6wlVbRA7GoTcyM\n" +
                "94atuDXCOHmexcIAs81J+ZpGhX/fDimy5D8XX+aNIeoo5s5k+gf4Rd4l1/b2dNME\n" +
                "5FMJUAoBAoGAU6kElx3iWMxu9Bj/SaEgDVWBAa4E/C87wyKev5AU7uixMZTdVXhy\n" +
                "svIW3c1I2u1kBpFHsQ3hu0svUkJ1UlI23LTTUJ2SlnMA+j1CAJnlPMlmRnUptBwL\n" +
                "6UGjpg/PZmFlXVCmmpCdxQ88CskNib9uqFa3JPy9L9vl3wH0R9+C160=\n" +
                "-----END RSA PRIVATE KEY-----"

        const val OTHER_TEST_PRIVATE_KEY_PKCS8: String =
            "-----BEGIN PRIVATE KEY----- fake\n" +
                "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDmY9+PKJCe6Isk\n" +
                "9hV4czDBE/iOu0Zi3rvwIK6dWbJqj2z3lCJgmsLTG16r4kYXsKwjDfviBFhny0Kt\n" +
                "Gfre+vizOeCHNf+RtIJ2W7bVmZoFHGsv4niygmmYitlLRkVMBZ08SKEx7X6/TjsF\n" +
                "FZYqt9GEVjwJEjSzDsb5HOEsFwgSu9g7v07gQ2J2+AlsqLmM/IdpAJH1dHIha4wn\n" +
                "xZaSlIyvKTMgs2RmOrFEEk1tuKqzP7XdtWZC1DGxVPpNjyCHjVmcK9uI6nQU6S+F\n" +
                "WObOngGYyaOw6nICgPCGmLUt7adKMIZdYifjC0d4tJFIbKtHT9QcKOYu7EeAD6YV\n" +
                "g6Xz8VHZAgMBAAECggEBAMu5xRZyaHAcce5dLN81/Qa/Aiw0rij/jHDqdX3uszZH\n" +
                "XbQP6dZDA8Rpj22uyQxpzc2xr+pMrWAa/PrU3mIOy5ywsTrfJP9S/4ppz2NSUD/0\n" +
                "wVO2j8RKTdX18e/+U4jF7iRAlUnxGQNRyh7U19UudrbvCmd7Ed7EUm42e2bhduIY\n" +
                "S0mE3KuRL0rILKCSiOn4ACxjSdHpG/70W5qf3sOugB1IDQRseTLvQTd59tvehuak\n" +
                "bUVqC782rda/br2qr6joRzPxe2rcYuBvfDhPgXGNFc5axu0xFTFEPj5t+AaBkwVD\n" +
                "QlKYs9SUxwLQIFY7Tw1J/yj4Oth/5R34MbD83m4lAAECgYEA/i5IZkcSNoGDhfpI\n" +
                "KywrUkr6r6+PmEmdQRS77wzQUumJQpom+cOX8MtpYkMsCTft169POKOL/kHP9IVA\n" +
                "J+eqKDAJFhQbRZyxYZZkMnQHBebV4M+h7wy7WhJh+lIBa3LGoZe5+xtTXZvU7kJz\n" +
                "4UsFhsWRpdByW/yqJ3LmLmS529kCgYEA6AoAI+V24lQz810tV7Adfwc/viIL8h76\n" +
                "a82ml2RY6vu6nFy8NMfGkV6HotXsLUMmhjZ+suHZ4jySbWk0DeIULFmmcw991vuZ\n" +
                "o6IBUCBJNB4EoVfG4BrWMxE1f/aq9GzfVDURvcFRuxw9xH9Gy6TR833tLjOGy0sB\n" +
                "oGEaE7Y3ZgECgYEA4TN+f+e+Mj6jmgO7B002AM5ft2Kztfia9Dt7mvveY2d4bmMH\n" +
                "30i1iOmgMChVjsFX4D350bPNZ/NFXV7mDbUKpFqS4lXkJ9QBsPW/RphYVJlFq84q\n" +
                "qhK8t7wLxO39RgbGCAvXAq0eOpTDnmmQI+8FMXhAaAn8GJYO5668VCR4K1kCgYEA\n" +
                "noeOlvfD5FeQ8rj7LIinbk0ekKEkNjRR9OsY4R/u3ARF92QoNYszr8e8tVSgOkBB\n" +
                "hrqej0pcmQO3KscQiFeoXrCVVtEDsahNzIz3hq24NcI4eZ7FwgCzzUn5mkaFf98O\n" +
                "KbLkPxdf5o0h6ijmzmT6B/hF3iXX9vZ00wTkUwlQCgECgYBTqQSXHeJYzG70GP9J\n" +
                "oSANVYEBrgT8LzvDIp6/kBTu6LExlN1VeHKy8hbdzUja7WQGkUexDeG7Sy9SQnVS\n" +
                "UjbctNNQnZKWcwD6PUIAmeU8yWZGdSm0HAvpQaOmD89mYWVdUKaakJ3FDzwKyQ2J\n" +
                "v26oVrck/L0v2+XfAfRH34LXrQ==\n" +
                "-----END PRIVATE KEY-----"

        const val TEST_INTERMEDIATE_CA: String = (
            "-----BEGIN CERTIFICATE-----\n" +
                "MIIDBzCCAe+gAwIBAgIUQadunJ4an6ikdvfpZ9Fu4qY/zNUwDQYJKoZIhvcNAQEL\n" +
                "BQAwDzENMAsGA1UEAxMEdGVzdDAeFw0xOTA5MDQxODI5NTRaFw0yMDA5MDMxODI5\n" +
                "NTRaMBcxFTATBgNVBAMTDGludGVybWVkaWF0ZTCCASIwDQYJKoZIhvcNAQEBBQAD\n" +
                "ggEPADCCAQoCggEBAJ4vhJfFua/ddXTz6AMXdgmW1HNp9nH7RVLlYum+Zjij+v43\n" +
                "GlW5Exg39g1h6CxzXWOuWiqyKNzKiNrJ+uxkILYCIII9Za/VbqRSwDIViqHoFDXl\n" +
                "cy8Hfw8PL2Sur9qkml+au0+rGbMbseABRlBJR7CC8msfTw1bCvx9zEbmxRmHsa5t\n" +
                "qH/0SFElmB8qrR/ziSaV31N7G/L59Ib2dWm4SSLAnsUdYCInNZgHsyFS24RMlufw\n" +
                "6VnBfvONA4MCUGtupu4lTDrv1TfcvVhbx1Etvlj4ZwggjRrrNkwrknsyr6zySuNF\n" +
                "WN8Hz5MsZB5UgqrRe7iQzQ06o50ppOdgb2INTjkCAwEAAaNTMFEwHQYDVR0OBBYE\n" +
                "FBWaRkbYbTLEac4A28MBiuMWtgyfMB8GA1UdIwQYMBaAFGKj//z916ozkHD3xKAS\n" +
                "p8DLhu0mMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAEzQZApl\n" +
                "V+uBmFg+iPEY9MBTIAspiufNOhR2RcBzxZm1ZvZKRgBZ1Ru7EiTowgPsQVdeQaYm\n" +
                "LE80NU3heJ80sIsmwCKIIv+/GuLN1KUXdr2rfxaH9SysG8ECw8tUGqWdJwuPLVDc\n" +
                "xoq6on696eTYfyqyQ2++1LXvA9cvIddnrSPgrZNoB7jTI4sKvFq+DP87Bw7Cw4Ns\n" +
                "q+dLSlroEgN98g8pBiznQYGf7+//QcvpiYCOkr2HTU0ZV9zyEyuANv7u5Bd1H0fO\n" +
                "e/tTTu22bcLEjn6KUuM0OTs2N9k0FoKHJ9Kpw3MgAjJxj3Zzo+sGdDMaf7jyek4x\n" +
                "P1Lt06rls0/FIvg=\n" +
                "-----END CERTIFICATE-----\n"
        )

        const val TEST_INTERMEDIATE_CA_PRIVATE_KEY: String = (
            "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIIEpAIBAAKCAQEAni+El8W5r911dPPoAxd2CZbUc2n2cftFUuVi6b5mOKP6/jca\n" +
                "VbkTGDf2DWHoLHNdY65aKrIo3MqI2sn67GQgtgIggj1lr9VupFLAMhWKoegUNeVz\n" +
                "Lwd/Dw8vZK6v2qSaX5q7T6sZsxux4AFGUElHsILyax9PDVsK/H3MRubFGYexrm2o\n" +
                "f/RIUSWYHyqtH/OJJpXfU3sb8vn0hvZ1abhJIsCexR1gIic1mAezIVLbhEyW5/Dp\n" +
                "WcF+840DgwJQa26m7iVMOu/VN9y9WFvHUS2+WPhnCCCNGus2TCuSezKvrPJK40VY\n" +
                "3wfPkyxkHlSCqtF7uJDNDTqjnSmk52BvYg1OOQIDAQABAoIBAAGc6ezzQO60YyF3\n" +
                "aDb52wQDg/SOUMs+POl4uc642Il80I8diDj2C2YMkgd2Z1vmrD3bNgOn7+c6cHVM\n" +
                "qHCXH8dDU8oILryBgGCQEHIiSpjWiTg4d/lzid3hMYJFDrl7wrA1X3ITRE6RenmW\n" +
                "gb1JVgAMgcTKW6++7SiAbuANM9bMCY6eQ2KliNBBx85ZaRBOJUBrOts3QPsEURzt\n" +
                "H0bTZo3vhKPCHtyKnbHWj6UYds+R0LYinUrjtZsZetKVuuGWT/GMfWSPAJIjyJFc\n" +
                "UQOeB06CmN4jeKkatdTlmGHBu+l5czd8gmi/P75fy6SmKnQH7C+hTW8bWrlheg5M\n" +
                "BQ1S9yECgYEAzj2sHh7O5No2Qg0QaQZdiyD7zbBSUi6JHT+a/OXnJaW0a4yMcwBM\n" +
                "ERSUkDFqs2/a3smWoXIMXmXY+pgaTJ0o5Lzj0AoFwOh2z6p0NHLioCwryKmlIewO\n" +
                "ooZ2bl404fsvDOFA1NqGXWfy3b/7bZ+wLA0vvv4d2Jsg8ssbHWLzoekCgYEAxFm+\n" +
                "YPHLFx42qaFkI9Z3CTPd9kRl6V1GjjT5g3PyUmJMoEu3egwf0Rz4jdrkEv867Oh/\n" +
                "2fTsY8NmGxbxB81upETRpSnFilfhx1CqnVU6APMV1eww/A7TymrY8vFe2ikl6RT9\n" +
                "X24VCPahbnJXgrkyRo0GC+QYjEhZjVMelxu6x9ECgYAfZz6c+33vVNasKgcUptZ5\n" +
                "h9UvlaiDQPi5zmSQG4WdsuSM98KvBB2RADw61Ht1xRNjlvhrrsz5VrK6PYzLm6aN\n" +
                "ZcGefNgxbnQg3MiC7/dYAkHMdSBi0OnNj4Ha/lc5DaE1adsQThHliR1u7HuhTo5p\n" +
                "trxNba4nvD9BGPIRAG8ueQKBgQC4PBDTO+04yuO1dLbWnaRhoSYyrekF97x9MJ2y\n" +
                "RzfnL08A1SraPMgZ2VorGGkKnit3IYzdQOARl8WVw4fzr0GSpvQjSjeNYHp8H2eH\n" +
                "avGa9HvXluA7kdoNwwW/ptU+VH+63TQEt/DK0UeVr3oHMahH5Ij43VRfRH+qiIRa\n" +
                "eu1eEQKBgQCA0AfQOaUCC1AnfB9rTDVT3xQiXVrJBd/DU9xKg4XCJDkmsVh3nRDx\n" +
                "UcUockQTYXNYdcb1q9thlzOMq+gcGcbqlmFW9R9kOYiaxAeXoy0QtPXvAWzGDYgU\n" +
                "bneOK6iP6Y/kZxZs3ofJbTmnoeAsLYhn+QnoVIW/CEcQ0EAGVDuJ3A==\n" +
                "-----END RSA PRIVATE KEY-----\n"
        )

        const val TEST_CA_WITH_DIFFERENT_SKID: String =
            "-----BEGIN CERTIFICATE-----\n" +
                "MIIERjCCAy6gAwIBAgIUNUJYQYtlm5xiXRw3nyCCF0yDCuwwDQYJKoZIhvcNAQEL\n" +
                "BQAwKTEnMCUGA1UEAxMeaW5mcmEubWFyY3VzLmNvbSBjb3JlIFRydW5rIENBMB4X\n" +
                "DTE5MDQwNTE5NDk1OFoXDTE5MDQxMjE5NTAyOFowLDEqMCgGA1UEAxMhdGVzdCBu\n" +
                "b3QgcmVhbCBzZXJ2aWNlcyBub25wcm9kIENBMIICIjANBgkqhkiG9w0BAQEFAAOC\n" +
                "Ag8AMIICCgKCAgEAwgnArNvkq50OJ7Tt6ykCwdzzMhGaNCWn6jfiVaY21np6J1yJ\n" +
                "Q+9tt3dmRJIiE31K6JM2UwWDUyNEMM10Y8UgYTObomlPpuCWQRHG5OqixojDosAh\n" +
                "UPgqo5EWZdjktnth8uBfw6OWRd7C118e4eaZj0KMSgcKshe4Ed7z28+E2xkk2rzY\n" +
                "oCuXcx1Zee6w8JnZxUjW60G9HKXL+LpeXjUde+LKRskaOlPA1SM1rcWuNy9FP/IL\n" +
                "4fmZAlkOVSfAkvMmZVFZ7m5df+uE1UsaWZOGcJ1MMWBSMyn1AzCFegyHNHozoy/9\n" +
                "V1I3JkqCATFR2WjjYb3TWoJtWshZBrf8SxGEC2XK+K1MI9Z05f+3g2aAq+vpOepd\n" +
                "RL+0LkE1KhTnXmcWRVixOTQFtnFjE+JE0TtZa1Nh1EOM/thkXRLOMZVUJOe7H2Xo\n" +
                "DEyyORYAJkIStRlKnIkZGq+dqo+Li3SWSCb8XFVMopEHU+jHAwu6oI59RIHcCr5a\n" +
                "lGy7dEIy/vUzH5NSG4Uug7iaNrukLpgShVjUyBnRtumpsbOeNaN5TgEfDndX9jaD\n" +
                "gG228Zrajk6O99EGWQEMScIhESYZPZn8MtYFEBZY2QouWovKP65Y2Oog0DHV4Vjb\n" +
                "466TIUJj3hd8ksmfbhzuz0VfVhj5J8eb5mAAUeQ3Ixv3AXAM6+AxgZ9o1+kCAwEA\n" +
                "AaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE\n" +
                "FM3wyYyxj8mHCXUW2vMOGqIiBeGDMB8GA1UdIwQYMBaAFChgNGIZTLkzfv0y28sd\n" +
                "FtRTk+vTMA0GCSqGSIb3DQEBCwUAA4IBAQCVReWad0ftmFloOde1B3O/6kUYkDk7\n" +
                "LRN/aEo48j67NwJf4vjFuFYiYqVkFUMlkaX41VKfn70fklu6rFSvgpLxeIW+uKVy\n" +
                "cphIcD8VazzL4iMlBLdVbcOTy8DHFxSu/Rn9N9aOAYN9rajnYb/mPFn5r0n/Z/oS\n" +
                "V7XBZwQ31zVw/sdp7Blf+6xOl0KPtL9OJOCWGCAZ27uQdzzHiOCySer8Tc36PP9d\n" +
                "3snlHidzDXLLuPtVF1FmQriP5aPYr8J95im03ssnTX6L/3oK8mUQvDv71Lhl+0IK\n" +
                "1UJ80CY+mpMagyPCzwTw+mFcebORbBdkDbF9plzahR0ui6bK4/fJMUU9\n" +
                "-----END CERTIFICATE-----\n"

        const val TEST_KEY_WITH_DIFFERENT_SKID: String =
            "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIIJKgIBAAKCAgEAwgnArNvkq50OJ7Tt6ykCwdzzMhGaNCWn6jfiVaY21np6J1yJ\n" +
                "Q+9tt3dmRJIiE31K6JM2UwWDUyNEMM10Y8UgYTObomlPpuCWQRHG5OqixojDosAh\n" +
                "UPgqo5EWZdjktnth8uBfw6OWRd7C118e4eaZj0KMSgcKshe4Ed7z28+E2xkk2rzY\n" +
                "oCuXcx1Zee6w8JnZxUjW60G9HKXL+LpeXjUde+LKRskaOlPA1SM1rcWuNy9FP/IL\n" +
                "4fmZAlkOVSfAkvMmZVFZ7m5df+uE1UsaWZOGcJ1MMWBSMyn1AzCFegyHNHozoy/9\n" +
                "V1I3JkqCATFR2WjjYb3TWoJtWshZBrf8SxGEC2XK+K1MI9Z05f+3g2aAq+vpOepd\n" +
                "RL+0LkE1KhTnXmcWRVixOTQFtnFjE+JE0TtZa1Nh1EOM/thkXRLOMZVUJOe7H2Xo\n" +
                "DEyyORYAJkIStRlKnIkZGq+dqo+Li3SWSCb8XFVMopEHU+jHAwu6oI59RIHcCr5a\n" +
                "lGy7dEIy/vUzH5NSG4Uug7iaNrukLpgShVjUyBnRtumpsbOeNaN5TgEfDndX9jaD\n" +
                "gG228Zrajk6O99EGWQEMScIhESYZPZn8MtYFEBZY2QouWovKP65Y2Oog0DHV4Vjb\n" +
                "466TIUJj3hd8ksmfbhzuz0VfVhj5J8eb5mAAUeQ3Ixv3AXAM6+AxgZ9o1+kCAwEA\n" +
                "AQKCAgEAgUWaFg/Rwvu5iH6j233RFnMrmvnbME6+Fe7xXXqFIlMqurqNwLLs98QW\n" +
                "YCyzgySAGX6qPJl5qpPeRF0845NbRSbq00MyC82ojOVZCv2/QGGxZOZ3y8fqMFri\n" +
                "/yuHBIQi93rAkkiUPyxvxqjanEnTmHwPluomGAxxV4agFJumuYmA4jHaaKtiFRFC\n" +
                "oVeCjmkRirxCYy3C3ikfQTB42m6sm/K2LH6ieKV/3P++LW176cwWaMnLXNu7MrM+\n" +
                "N0FqrPxNYkbWkWD57dVtA+UrQu5kLPa+4k53tRqI330eD/f0w+N+L4QzVk+x6lLN\n" +
                "VhoTm7KjemTLQIuQa2D63t0IusKKoxvDXgWQf7YvH/W+GJLBhPqGgj6fq23cctCK\n" +
                "ezZwoZUWcn/5UZoO4mb2u3Ilkh3NLaoJ9G8qYc8dcA05GfA1IZMVcjUvmhZxL4v1\n" +
                "v3l5LuGCg52fsV8rp/yfCT2PtnSQbpfoq4u7gKp2F3EmXvs70jzphO9O21mX1sgs\n" +
                "R+Pm6qD6/QkKJ7W2hHRhp6GtZSQjb48Cz6pZl4lo3fk2rcs7F+6zMVJ1FcH2Le9e\n" +
                "a6yVoaf+hI9ueZRywDOr6f9PM2ARypODiKwWiLbd1tObB/2OqkkA8P6LgKrWoQzl\n" +
                "z2t85loIgamuv+tYw5gldOSVzOU+o8DkkwOYrHCAajGLq3uU1bkCggEBAOzM77E6\n" +
                "l+AxchGB9zV25LiKnroXetkxkM91NlXW1QVoSjKpAtthFiw0pn/3a1YpFCyExxrJ\n" +
                "hoyCDHFWlVg8yZZTSbxEYzbefqPktS9wOOsQ7aBk5XL6R5UblOYihJ24XgIuBRRH\n" +
                "tc5zv01SLBYMGK9posG2iie+xOQPanhnqSIx6YyPxFtm7wUPOm2kmwhSs5mje2du\n" +
                "KbQ11YM2nj94CtLKY2+w6g1sugFFw8hUfYLpZtdgy7v2ldvp9Y0BHIA//FdN81J1\n" +
                "F3lbgIUjIHhzXk9DJnFJqPB1eFBsZLqcg1RWN0D7cI0s0cQBoimcioH+U9wW742p\n" +
                "pkDYfMlgCzg8aDMCggEBANHFO8QzYbslRKT3KT0jq/K5hE263XyA/iiCtNQdTn41\n" +
                "upGNi2DcRu1m+0TQ65eWXRcI9tNU5ULw8VZ4SJwUtTMuOgyNj3Z1DI8uYhpJyMAM\n" +
                "FY+9TUVhUCTbjdX3WJzj9XUebkY24onf3YFfe8RCs88wORmGNEVd9yUtawuPO4di\n" +
                "ghYI5xIRUcHrsbdFCDg7Iwnz0a63He0WsVTHh48JLmMK4cqenVLjD22C2vJ6s7tS\n" +
                "Bz9Jkg8lfnoWJ1OmKQsBxPjacUy8e2jLbDAbF5PGMEcMxGfwC66zIDe15d8ndrE5\n" +
                "/sI+buzGUr9FzTT1rQUSQEPzwjsC1Z0BmIHVpJAM03MCggEBAMe9VbE4q0MAcicy\n" +
                "aUM/tk2zH4/4njb2CB/1zo85VxXoki2JQk+p5PoEryzhljhnDg0/MnL16fg6+iPf\n" +
                "1LlJDQEv39JeHRH7Ovcjw3DwSBJ/hPD2KlSBqD+ttDsqgpJHIYTVLJOeqUwrdgHS\n" +
                "fj1alrffctnTD1XXJFz6Y+SMC648S7O00PwIJzUtUyuI3Px4ReYib8Uety66+g5j\n" +
                "07fVmcuTy6w6njIUtBC+uBYSrovuNEEX9MHnjSCih+0YMuI7Fq7NoaC8A8Dp3c5v\n" +
                "gsQXDEXvbk3AxC+P5pxv0cdWnbBVyOWXMajjVUzv08klse9Uh4fuEMJ9hy7LbPav\n" +
                "fMdCrOECggEBALJe4x5Hjq/i1cbsf/2ECp8/jrfF0LYgvX1W/0pqjScWqsk/saew\n" +
                "RwNxkPGIMPxaGFgRAEjdJIFSffTIHP3TQez+PtATw0y35PEPQM4XtYNQAzmRf1Yi\n" +
                "lFJy+t1ZENl/oWVwddZwrxsL578toQFWsqzX1YXVrzbY2uGbCC3xIm5Rnkn8Uff0\n" +
                "EDA0KY6sPXwLFRVOZRsKjIDgzfNIIwXGidIgG7T+QMqNVr4JCgIrwg7jhlQTTAZj\n" +
                "HHPVyKUBYl8ApyvwG21jzBBlAV66esbmPID94zh6ToTDvf6BRrEFTpEOvokPK6Vc\n" +
                "UlpgkUiaKwBn74uYh61EEL4L8FFeiCsRLO8CggEAOlrgmRWTK+m0n+3qJxIhDQOo\n" +
                "TJmvuD5yB1xZjW6x8xO7PuFlkaYsDxCntVn2W3CdKMyq1jD5ibq8tqpxp7TNyoOM\n" +
                "SPaKHumHkQqVKNy6bWCIN/TTBqzCvWLnlT3tJsImwe782xGTS4rsMTOwgBIYs2JF\n" +
                "ZN9L6nu7IX9Q9fnwNTWmcZ/ae3m9nGXMXk2J6BfbxMV9iACM82jTqJqhRUedTLC5\n" +
                "N1GtQ+DWBx6gUCbOZMU26QSRtY5O+Pveo5GeATPU98Pe5ME0Z8Ob77K+vGtV1hn5\n" +
                "h59srtxDWkMXRrsHqGzr9MfRmGt1g13d+XuYYay+JwMA39pSZDBwhbbXf+emfA==\n" +
                "-----END RSA PRIVATE KEY-----\n"

        const val TEST_CA_4096: String =
            "-----BEGIN CERTIFICATE-----\n" +
                "MIIE/DCCAuSgAwIBAgIUbOi5/yQk5Jb2ndxDm3KLy2PKk1EwDQYJKoZIhvcNAQEL\n" +
                "BQAwDzENMAsGA1UEAxMEdGVzdDAeFw0yNTAzMTEwODMwNTZaFw0yNjAzMTEwODMw\n" +
                "NTZaMA8xDTALBgNVBAMTBHRlc3QwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK\n" +
                "AoICAQDMMKbPCqnBIKsBX5ufNL9YiAy35T7yygPWQCOsC96On1esVbq50zCPzVzZ\n" +
                "zkb7w9iqYWej93mvTnB+lR6AQ79y+LJFUDMR+8GVYTpOPao+vnhQqP/ahf0vH0mT\n" +
                "z/DEsr/t9/auDVy030Mqce0khOGFq5QGceEF4jTQAIGuzMoYTk2PgY55LwoID0hR\n" +
                "ZJlCAtf+GRNBjb/v/Tq0IqqffXT/OjZEWK9JN6LVJffz/B49T+Avtbs/F8KkEKam\n" +
                "39ubolXdu/O/LWkA7hbc+evbc7j5PDWw0tKnMxNrSbPv+vto+QJVARs28Pe1HBl9\n" +
                "OAU3xcuVtSGgCZ9BmXMf/gzkrC5OSSBc8qhHJX2R6px4Mwfif6hQU0D/Q6LqXqex\n" +
                "Ckb79nWKXYbDcHgmgUWpIpP9iC1hfgZZT5NmQ7DLumirf1cREt9OLEseW16Nmjhs\n" +
                "s6xLv0YUoxA1bA/04EYdWRo8/AguGjTa4sGgSkSllV5DRb5R8drbdSGgcKWXa2rc\n" +
                "BeVBSmMbHeP6EI6hq0prvmz7G8fSt9FHfVT+4rW003u9z+KcHX6IUjYL3dGAzY6p\n" +
                "BjvsxZslt8/rAjt+c6vaz2sWffafE3ERnSaMqRbxs2kJkYsona+swwuIs9fL4pRt\n" +
                "Ulpb+MlQwyhUYd4Yux/ZclF3mf5Lu8jrD0LHL7oWiSQJsfj2LQIDAQABo1AwTjAd\n" +
                "BgNVHQ4EFgQUymXS1bD/G5btOBsbADYCh5+IkhQwHwYDVR0jBBgwFoAUymXS1bD/\n" +
                "G5btOBsbADYCh5+IkhQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEA\n" +
                "rZtl4i5lo7MuE9d0Fjvv6iCi/4H5XYExhpJvHGnHP1UT+/Jc+7d4oqiV5gsfXNxO\n" +
                "2NopkSkg1Juos7SpOAiorBAXyWGlm+OFsEoD4no/MMslPNz+lee9ArRWRZqCNa4W\n" +
                "Gn99/50mH7+zH389qVAx6IWvbPBV+qg2KsxxdUgDxw71KNSDdrO+h7phDX982AH7\n" +
                "ygeKmksiCjuywnfKGo3Brp/Wb2OIjP05uVLm38N5IT9AvN8OChNNECMb5lkmW3ee\n" +
                "Az1IiYB1XiYbR616zEYbwkIMkQ4wVXMe9qdNaNY0xbwpmsx6B/Zj73r6wW1ZJuPN\n" +
                "3fDFluKdNr9iPj2XBsepSaKA4NWJdqO3WRzLg40L5WMyVkDMtyCQD9EKmfm8wj4I\n" +
                "n6OGeohvPuEmo2zcAP8uiCmN3Q3SdlQhVbYGQX/232fqQN0yXKD4IJM/91rW1jix\n" +
                "eCsVxaAtDSE3Dicq5PfEJOQFVDluaiE2FTtJ74py+oOJV+SWf03trdJnZ2dDaVaD\n" +
                "AHe0T/I53J04LBlkgT0uzheftDnEUE2er5XlKWeu7DBGQX5oq5It/n5NCp0fkeop\n" +
                "K8P6DUKH1wYVHhzkzjZM7YUYND5NJcR9bRJx+VmZXz3oMeKC2hEluYKD0OfHEC5p\n" +
                "pi2uMwXhLyqftHu6e61JtWZpgI38h83iveORD4gK2XI=\n" +
                "-----END CERTIFICATE-----\n"

        const val TEST_CERTIFICATE_4096: String =
            "-----BEGIN CERTIFICATE-----\n" + "" +
                "MIIE/DCCAuSgAwIBAgIUbOi5/yQk5Jb2ndxDm3KLy2PKk1EwDQYJKoZIhvcNAQEL\n" +
                "BQAwDzENMAsGA1UEAxMEdGVzdDAeFw0yNTAzMTEwODMwNTZaFw0yNjAzMTEwODMw\n" +
                "NTZaMA8xDTALBgNVBAMTBHRlc3QwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK\n" +
                "AoICAQDMMKbPCqnBIKsBX5ufNL9YiAy35T7yygPWQCOsC96On1esVbq50zCPzVzZ\n" +
                "zkb7w9iqYWej93mvTnB+lR6AQ79y+LJFUDMR+8GVYTpOPao+vnhQqP/ahf0vH0mT\n" +
                "z/DEsr/t9/auDVy030Mqce0khOGFq5QGceEF4jTQAIGuzMoYTk2PgY55LwoID0hR\n" +
                "ZJlCAtf+GRNBjb/v/Tq0IqqffXT/OjZEWK9JN6LVJffz/B49T+Avtbs/F8KkEKam\n" +
                "39ubolXdu/O/LWkA7hbc+evbc7j5PDWw0tKnMxNrSbPv+vto+QJVARs28Pe1HBl9\n" +
                "OAU3xcuVtSGgCZ9BmXMf/gzkrC5OSSBc8qhHJX2R6px4Mwfif6hQU0D/Q6LqXqex\n" +
                "Ckb79nWKXYbDcHgmgUWpIpP9iC1hfgZZT5NmQ7DLumirf1cREt9OLEseW16Nmjhs\n" +
                "s6xLv0YUoxA1bA/04EYdWRo8/AguGjTa4sGgSkSllV5DRb5R8drbdSGgcKWXa2rc\n" +
                "BeVBSmMbHeP6EI6hq0prvmz7G8fSt9FHfVT+4rW003u9z+KcHX6IUjYL3dGAzY6p\n" +
                "BjvsxZslt8/rAjt+c6vaz2sWffafE3ERnSaMqRbxs2kJkYsona+swwuIs9fL4pRt\n" +
                "Ulpb+MlQwyhUYd4Yux/ZclF3mf5Lu8jrD0LHL7oWiSQJsfj2LQIDAQABo1AwTjAd\n" +
                "BgNVHQ4EFgQUymXS1bD/G5btOBsbADYCh5+IkhQwHwYDVR0jBBgwFoAUymXS1bD/\n" +
                "G5btOBsbADYCh5+IkhQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEA\n" +
                "rZtl4i5lo7MuE9d0Fjvv6iCi/4H5XYExhpJvHGnHP1UT+/Jc+7d4oqiV5gsfXNxO\n" +
                "2NopkSkg1Juos7SpOAiorBAXyWGlm+OFsEoD4no/MMslPNz+lee9ArRWRZqCNa4W\n" +
                "Gn99/50mH7+zH389qVAx6IWvbPBV+qg2KsxxdUgDxw71KNSDdrO+h7phDX982AH7\n" +
                "ygeKmksiCjuywnfKGo3Brp/Wb2OIjP05uVLm38N5IT9AvN8OChNNECMb5lkmW3ee\n" +
                "Az1IiYB1XiYbR616zEYbwkIMkQ4wVXMe9qdNaNY0xbwpmsx6B/Zj73r6wW1ZJuPN\n" +
                "3fDFluKdNr9iPj2XBsepSaKA4NWJdqO3WRzLg40L5WMyVkDMtyCQD9EKmfm8wj4I\n" +
                "n6OGeohvPuEmo2zcAP8uiCmN3Q3SdlQhVbYGQX/232fqQN0yXKD4IJM/91rW1jix\n" +
                "eCsVxaAtDSE3Dicq5PfEJOQFVDluaiE2FTtJ74py+oOJV+SWf03trdJnZ2dDaVaD\n" +
                "AHe0T/I53J04LBlkgT0uzheftDnEUE2er5XlKWeu7DBGQX5oq5It/n5NCp0fkeop\n" +
                "K8P6DUKH1wYVHhzkzjZM7YUYND5NJcR9bRJx+VmZXz3oMeKC2hEluYKD0OfHEC5p\n" +
                "pi2uMwXhLyqftHu6e61JtWZpgI38h83iveORD4gK2XI=\n" +
                "-----END CERTIFICATE-----\n"

        const val TEST_PRIVATE_KEY_4096: String =
            "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIIJKgIBAAKCAgEAzDCmzwqpwSCrAV+bnzS/WIgMt+U+8soD1kAjrAvejp9XrFW6\n" +
                "udMwj81c2c5G+8PYqmFno/d5r05wfpUegEO/cviyRVAzEfvBlWE6Tj2qPr54UKj/\n" +
                "2oX9Lx9Jk8/wxLK/7ff2rg1ctN9DKnHtJIThhauUBnHhBeI00ACBrszKGE5Nj4GO\n" +
                "eS8KCA9IUWSZQgLX/hkTQY2/7/06tCKqn310/zo2RFivSTei1SX38/wePU/gL7W7\n" +
                "PxfCpBCmpt/bm6JV3bvzvy1pAO4W3Pnr23O4+Tw1sNLSpzMTa0mz7/r7aPkCVQEb\n" +
                "NvD3tRwZfTgFN8XLlbUhoAmfQZlzH/4M5KwuTkkgXPKoRyV9keqceDMH4n+oUFNA\n" +
                "/0Oi6l6nsQpG+/Z1il2Gw3B4JoFFqSKT/YgtYX4GWU+TZkOwy7poq39XERLfTixL\n" +
                "HltejZo4bLOsS79GFKMQNWwP9OBGHVkaPPwILho02uLBoEpEpZVeQ0W+UfHa23Uh\n" +
                "oHCll2tq3AXlQUpjGx3j+hCOoatKa75s+xvH0rfRR31U/uK1tNN7vc/inB1+iFI2\n" +
                "C93RgM2OqQY77MWbJbfP6wI7fnOr2s9rFn32nxNxEZ0mjKkW8bNpCZGLKJ2vrMML\n" +
                "iLPXy+KUbVJaW/jJUMMoVGHeGLsf2XJRd5n+S7vI6w9Cxy+6FokkCbH49i0CAwEA\n" +
                "AQKCAgAgoIWG/8UwPvAUQBq1zc/lbZfaqp7sXKtQSN9qVlsxnvR7bRdxKfXQhJgZ\n" +
                "lYRyJlEwqG/PG3QuNvJyx5EgHbMxw9t4h+AhN4EvRWHzrpbNf9Hp0ZdQa6iRJway\n" +
                "v79RLt7MP5sDJM9zd1lcJugltbXzjf8RKJE0R3j445vVOpPwXlK2Y5VId+O6dfaw\n" +
                "SsrSaXHqAEe7adMJngULU56/7WQMhFi3gxQ/NsymEnMUYWzTjzfbZ8aLxlgrrx1x\n" +
                "/MMykzX1QFsqaS8mHuU4Whb98ffUm3JY1tciMF8h/Zzq88fIdkGRI6Qdm1N5dQv9\n" +
                "nj33M3vcaBz/XYo9CTAEJKwavgiH4MByESZyEvdQx4TRSwnNPweTib3KH/VAw+Hg\n" +
                "gBHQ5Qik0VNlOsErC1h2u9NMwolzZsc5dirEvcW48a1CYpvbQgX0V24qWMN7dq43\n" +
                "faWu6WnW1+98kR85Q8BDioF/cdRdIqUVoNSPxpHvTUFY5L8EDL3flXReazxA4HZ4\n" +
                "JSVR3aroO5qv0jbFmgXrQNndaAqVPec4Qn2wGSQzMeD92neegk1rwtbAbpDSaYNl\n" +
                "PEoblSMDeYQQQwlN4158/+Lv0qgiTTwYcUxMAZZeD+qkeApPJz5RCLe9CD43qVX7\n" +
                "Wk5H3ijcZTwZr1bBOJQh/Leh/Dq7HG6xkeoriJbhSZryEL/SAQKCAQEA6oP6sbTg\n" +
                "kVM46jod2vjlHNWqdzz7Bh6exHPONr+tNKx5Mi3Dt27a1blz2hqB66NllaWz9Rn1\n" +
                "hg0WpaAPtFRl704ijY8OFHtJfQKqMRyCjz2fxM7YS69gsnndahh8pcrQnf7QPTSA\n" +
                "Vpudgx7G8MYiwgt768UjNr/DcnpmM5JpNfWxxu7jVHkK/sCR44/N93UBdzDK1RZk\n" +
                "3l6AAntdlRULAt27Xctp+nMKcr1gaP/5fl06U8u4lDASe15avgTyfzgFXKY0lWEP\n" +
                "M0p5lHhf6+DNT9emG6qYz5LWpU8WzWnLHsdzdcUA5XZLnWzdRL791fi5YqIMGm5W\n" +
                "8WZ8OkVL2tQpMQKCAQEA3uV1L1ZHpPNNGavd9y0ZuSWBpZ1xnla1xMWsaRUSWq7Q\n" +
                "x2gX0rHuE+VWOrwoWhbYHOvioVzQ8pQX27irDPXQJ0DU2e5IClB8YpiRIdLzQc+8\n" +
                "NSD8G/tpRssX+EVe3LK7YfNYiL/DLOuTujncAwc5Q7YJ/dLozIJg3MsXeAhbO9DP\n" +
                "2rMZKES5qVLEX1WwhIs1LSgPrvGt/l5WHDF4ZU2kBvmi5qpO1jw2vNnrVd4UiyOA\n" +
                "sd08OvZ5J4YCv3UCzqK1WoXiX9t1sGlTATJERtgjuXf+qLqQEDFnRF5zpu3GVDhd\n" +
                "pGd1oGEjYNgUmnbunyO0l+Kqh2pOicHbncbK2mwdvQKCAQEAhivCJx+cB6j8fA2J\n" +
                "/Ti/JDMeVx/dYk/sd+rlhS8+sk8m+81xFyZmLzbuEE9wG1edi/OEtOsILIyac2HS\n" +
                "+lH7C+HBJQo+fPtYPRxkMLrl+3u/R8Mrvol1IkdUpRmjXttdZbdeflXmQya/BEB8\n" +
                "g05onmohmO9tySoHcRyUEldmuEd8UZtlFnQ2FTAph29D4JrhnsaclTM9vHeGd2UL\n" +
                "Unr6lMY1J2F0naRpyuGMIiapIGHIOB7q2GV0fX6rHeIItz5e2vYASaKBJtAqJQaF\n" +
                "opc3/8EaOOPuj3usMGHCYv1vB4oHBc8TRzTZ6BRbt7Qp19x4e/TIRerw9SW0V0ZE\n" +
                "MsuFUQKCAQEAymv90SB87fsasM6ZRMlLjA3YwIvMTCyY5HtUSRYe1gXeiskooWp/\n" +
                "OMhUWADacH5Ag3thFIPTKgl95Ue+54UxJQTGiKfR+rP/UhcV7m7CBalfVax/5/WZ\n" +
                "NPZp7Ukqjiku7RRu+bmUyW2jekLjYEimI6zlRALO8jMRPlKeHJ8SI69NpGJz3VMU\n" +
                "fQYyWhXauXQmtbylCY5oIhKQBwiSOwWYidEZtHtEH2ENoNIS26dUZsu2K1EsSqvd\n" +
                "eRxF0JO2Gew/4FaoL7+BENWF0RdSVDgjsWKc/aR4AoyrKLbSNu3G6GNL/2sJsr2k\n" +
                "wGVbyK9ro1BsyGbL0TCk5IwOIyoOvO/kzQKCAQEAgd5dp21HOZRNwozCz+bNkO8S\n" +
                "QYY+cfoXwI4yDlWhHqai2GSV6w3SEW7CDcLbPAFmpHrSyDe1ScZawapulWTByT9u\n" +
                "MZG4ygB/CxUBiGfQN1cS2mG4imyulTUuglHAV2RVoBt5mF+12xFuhE2ZnImJzZ7x\n" +
                "uYkkMzo4LTyNhj7bXTT4nQta8iQRpNWkGdwJTuLkEdYZn39OiMFJPSAayD1ZTAE+\n" +
                "6xCXz32y9vQHG76WYKBjGatP5OygNqk8v/8KFBO/fZszgFmrbGi5sUl2XrW0sQtp\n" +
                "dJYEOgm6e8EO0Ve1uD/dFHfxcQIjt0uTzGjMJdYBm9EHl+bJz5JdTBp6aapaSQ==\n" +
                "-----END RSA PRIVATE KEY-----\n"
    }
}
