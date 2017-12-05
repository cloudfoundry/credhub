package org.cloudfoundry.credhub.util;

public class CertificateStringConstants {
  /**
   * .
   * openssl x509 -in <(pbpaste) -text -noout
   *
   * Subject Name: O=test-org,ST=Jupiter,C=MilkyWay,CN=test-common-name,OU=test-org-unit,L=Europa
   * Duration: 30 days
   * Key Length: 4096
   * Alternative Names: SolarSystem
   * Extended Key Usage: server_auth, client_auth
   * Key Usage: digital_signature
   * Issuer: CN=foo
   */
  public static final String BIG_TEST_CERT = "-----BEGIN CERTIFICATE-----\n"
      + "MIIEbzCCA1egAwIBAgIUYE3pB+BUaAP0YHeofpCmI/xCkmYwDQYJKoZIhvcNAQEL\n"
      + "BQAwDjEMMAoGA1UEAwwDZm9vMB4XDTE3MDIwMzAxNDMzNloXDTE3MDMwNTAxNDMz\n"
      + "NlowfDERMA8GA1UECgwIdGVzdC1vcmcxEDAOBgNVBAgMB0p1cGl0ZXIxETAPBgNV\n"
      + "BAYTCE1pbGt5V2F5MRkwFwYDVQQDDBB0ZXN0LWNvbW1vbi1uYW1lMRYwFAYDVQQL\n"
      + "DA10ZXN0LW9yZy11bml0MQ8wDQYDVQQHDAZFdXJvcGEwggIiMA0GCSqGSIb3DQEB\n"
      + "AQUAA4ICDwAwggIKAoICAQCk+byx2uL5QNAQqdeEWoD0NfuXdbtf/j7orjK7TjCn\n"
      + "djM21HLnIq96hZ+/Vxg30oxjRqAMKDUIj8OTrisorgcgpLNV7NwklPG9A0gv7xdk\n"
      + "YvxhnEnyrztZYiS8sx98YDwjQpJDeA45QX6+/9k8qmXf7XRQRRTqhkG8jpkk0vvj\n"
      + "hvwwTAma+0xALWfVBnhLJz82snJI+ezM9OuwO53iOkziNHNxtuc5sq/AjuDf48O4\n"
      + "HOtxdB27WniL0T3+4Ng8ZRAgMmlSrQdFn6x/Us32VTVLTD4x1s9H4HL3c8LZJaoD\n"
      + "CEKIwFRn2lSko4b4PAUGHZ0KpfeTlur0uR464s4PHh+EV1DOm/R/1/HIQgKanr5B\n"
      + "FzLONAqFPPCMB/hTPli+Q6nez+Q2alpyxEz/QTCTNROKl+opVWJW6gAPMXAkpqc2\n"
      + "bx0O7fRwwF9evVcQ1BZdfWaG3iGqO60o0y7lEAmvlOwnw0JjSta2NDlR0nNp9frx\n"
      + "85USPdMoSBoaAGb+BehbvFsVoRTToxCo0YwCDcGjgacR4oCu5zTZd0KUVlGJ0vpu\n"
      + "OJiUALyYSD/6mN8ZIfPa/rR8PF5ju3JzGd/AEh0F8gfgardLrNHre904/0HwBqvc\n"
      + "ShdSS0XHjA7nTLAyARgLU/E0TIL9DH63tWrB2W+m7vBMkU0fuY5c40QIalT/iGbj\n"
      + "8QIDAQABo1cwVTAWBgNVHREEDzANggtTb2xhclN5c3RlbTAOBgNVHQ8BAf8EBAMC\n"
      + "B4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAw\n"
      + "DQYJKoZIhvcNAQELBQADggEBAF6cvPlK7kuoC/EBmTF4OdTrqzKYa4bm47hn0e7V\n"
      + "3fmgt5YJl/HM/wQI5Dw37y5SjtCScvZUJQ7N+vKQ06bPJHea8f3+XwgsM0JpUhkV\n"
      + "djZR9L5LrJdwmhk4arbMLMKeFwB1Xir72trL1DreI/Kzsow0LbMhllLWPyRHmAhr\n"
      + "Kqu/WgGim6m3lVgZdx4o6cguGry+ceiunCwCFL36CL1AdvYL8ZnUlQDT1hNp3anE\n"
      + "QTHPRc0mETzHET0uL+9UpaUxglRPzuxVhyIYimXSiPQlk8K43gmXM8QKi85eo8xD\n"
      + "W5kgC9Eel5YQcs5wUS/1aW72x2D+7DeGxLjFwm0Sy9S8hfI=\n"
      + "-----END CERTIFICATE-----";

  /**
   * Version: 3 (0x2)
   * Signature Algorithm: sha256WithRSAEncryption
   * Issuer: CN=test.example.com, OU=app:b67446e5-b2b0-4648-a0d0-772d3d399dcb, L=exampletown
   * Validity
   *    Not Before: Mar 29 20:23:53 2017 GMT
   *    Not After : Mar 27 20:23:53 2027 GMT
   * Subject: CN=test.example.com, OU=app:b67446e5-b2b0-4648-a0d0-772d3d399dcb, L=exampletown
   * Subject Public Key Info:
   * Public Key Algorithm: rsaEncryption
   * RSA Public Key: (2048 bit)
   * X509v3 extensions:
   *    X509v3 Basic Constraints: critical
   *    CA:FALSE
   */
  public static final String SIMPLE_SELF_SIGNED_TEST_CERT = "-----BEGIN CERTIFICATE-----\n"
      + "MIIDZjCCAk6gAwIBAgIUD8qb4pWPNR6dhYtZgf5Cn5DymHowDQYJKoZIhvcNAQEL\n"
      + "BQAwZDEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTExMC8GA1UECwwoYXBwOmI2\n"
      + "NzQ0NmU1LWIyYjAtNDY0OC1hMGQwLTc3MmQzZDM5OWRjYjEUMBIGA1UEBwwLZXhh\n"
      + "bXBsZXRvd24wHhcNMTcwMzI5MjAyMzUzWhcNMjcwMzI3MjAyMzUzWjBkMRkwFwYD\n"
      + "VQQDDBB0ZXN0LmV4YW1wbGUuY29tMTEwLwYDVQQLDChhcHA6YjY3NDQ2ZTUtYjJi\n"
      + "MC00NjQ4LWEwZDAtNzcyZDNkMzk5ZGNiMRQwEgYDVQQHDAtleGFtcGxldG93bjCC\n"
      + "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMle5V28ZST5EvfqPLVk6Wg5\n"
      + "i7poGmtGTkFBhi4YSIhD/cKqMlc3eh7X0cm7JYbMtK7WJ/QTKEKfzrFB/NCmu1C7\n"
      + "840lo+9tA4jDuZksi6qclTcjPP5tvjeCkRhBXw1qOjHvT5doPIGsGYNzKIEjobRN\n"
      + "fPT1Z83laKO9x3JXatulpx3VrJCeAVZADEUYonCU+l5cplWxgh1Zy1rbVgx2NSoL\n"
      + "LYst208h9I6oq0X/u2VmiPIXDE8iblexvhQwrLE31R7AsGfsObGZ05KSBsZBJsyE\n"
      + "xmb5K44IuKahpZnkX9x95fuJUzYdxcjkR9KgSak2uLFY0pki87PH6bOoApDfnNkC\n"
      + "AwEAAaMQMA4wDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAvwGXYcQL\n"
      + "WNzts9Hx6Rih8Vj5ibORRl/49m820dFoxZzGmxwUiHFveni8cbkW3WkFEI6iUFRl\n"
      + "cH9SilytWi+WnQr8zPUC80OgyOUHd8JRLxn84cJBxqKsMvn2vhFYhCMhJSgzyIOF\n"
      + "2hCIx4uwTEizCeq/DWZJhSSbEkdGW2CCON97VyNAhUQ+lwkJG5cEDSEDmtqT8MD+\n"
      + "fCe0Wu650ipk2gGMZnbnRCi4phxb/bx0rEyq5upuOZw5Ja6/Ulikm4pF3mwW1xuR\n"
      + "OgN3QbqNnD+GGJnsddnTY2o900nXOki+v4tcnRTlfhnkWIXn3kF+ZgmacUQDdq+G\n"
      + "zNIcsYa7oxP46A==\n"
      + "-----END CERTIFICATE-----";

  /**
   * Version: 3 (0x2)
   * Signature Algorithm: sha256WithRSAEncryption
   * Issuer: CN=test.example.com, OU=app:7e0fbd7d-14bd-11e7-a8b1-10ddb1aa64b3, L=exampletown
   * Validity
   *    Not Before: Mar 29 20:23:06 2017 GMT
   *    Not After : Mar 27 20:23:06 2027 GMT
   * Subject: CN=test.example.com, OU=app:7e0fbd7d-14bd-11e7-a8b1-10ddb1aa64b3, L=exampletown
   * Subject Public Key Info:
   * Public Key Algorithm: rsaEncryption
   * RSA Public Key: (2048 bit)
   * X509v3 extensions:
   *    X509v3 Basic Constraints: critical
   *    CA:FALSE
   */
  public static final String TEST_CERT_WITH_INVALID_UUID_IN_ORGANIZATION_UNIT =
      "-----BEGIN CERTIFICATE-----\n"
          + "MIIDZjCCAk6gAwIBAgIULvDbv0eGhurO4sQHPGQzw1JZzBswDQYJKoZIhvcNAQEL\n"
          + "BQAwZDEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTExMC8GA1UECwwoYXBwOjdl\n"
          + "MGZiZDdkLTE0YmQtMTFlNy1hOGIxLTEwZGRiMWFhNjRiMzEUMBIGA1UEBwwLZXhh\n"
          + "bXBsZXRvd24wHhcNMTcwMzI5MjAyMzA2WhcNMjcwMzI3MjAyMzA2WjBkMRkwFwYD\n"
          + "VQQDDBB0ZXN0LmV4YW1wbGUuY29tMTEwLwYDVQQLDChhcHA6N2UwZmJkN2QtMTRi\n"
          + "ZC0xMWU3LWE4YjEtMTBkZGIxYWE2NGIzMRQwEgYDVQQHDAtleGFtcGxldG93bjCC\n"
          + "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKGehnx7S8uvY3jyuWmkZgY8\n"
          + "aCYQoIs5jVevYI5ajyyFX2F6sv6+4p0FDB1+9sM2/PIbyKHrqMcvTJwdgbW01nfo\n"
          + "mRipq91K07u6J387U78RS/XIwKg9OcxSn0RH1f32oSOqiS+miWmgek7kFrGM2hsp\n"
          + "ySPmTqr36m3Tn5Z0sy9u6B/2U1kfYMNhd0KEHrhQ6zGUfxiMXwVXm5JYsKHadlzq\n"
          + "xo1VqOSKzbVWayIlo+g2c1mcv0DXeXBcoKh9APAGKyjUwXq69pFsprq3gj45lQVE\n"
          + "8dp9ukRX4eWYgPxBublToJtUGlKth8s9rfhSVjhnkp7TT9WDor9G4/iPRna/KiUC\n"
          + "AwEAAaMQMA4wDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAQL89uAb8\n"
          + "wqS1ZlVNC6mGXLrrORvhCIS+2LI3Cllo87G055kATS3u5yGq/6EzAM+4W6LePg94\n"
          + "5HT3Jyo1uO/D9rNfgJ7+yxaotwr13p0L7yeKO3XT4jOaav0UIPFDq8TcMfADilOa\n"
          + "w1FHWyMxn3wSbD6KYzjEnpo932C+CtXfQPX+dtCayR/NO7DxhAbCfIhAZNIbA8xn\n"
          + "g8GslKQKmPFVpclGjRjeMOgSOdsN/Dg0OwzKBMSoWuUGLavICh0HwlccW6+cxgUs\n"
          + "Pswa7CjG14hVnFYnj3ISDrXetgwX3Gw4kbwFdWERzDrYvoNzdguKYkrop+mUGqpy\n"
          + "OeRYsf1HBP8d0w==\n"
          + "-----END CERTIFICATE-----";

  /**
   * Version: 3 (0x2)
   * Signature Algorithm: sha256WithRSAEncryption
   * Issuer: CN=test.example.com, OU=7e0fbd7d-14bd-11e7-a8b1-10ddb1aa64b3, L=exampletown
   * Validity
   *    Not Before: Mar 29 20:35:54 2017 GMT
   *    Not After : Mar 27 20:35:54 2027 GMT
   * Subject: CN=test.example.com, OU=7e0fbd7d-14bd-11e7-a8b1-10ddb1aa64b3, L=exampletown
   * Subject Public Key Info:
   * Public Key Algorithm: rsaEncryption
   * RSA Public Key: (2048 bit)
   * X509v3 extensions:
   *    X509v3 Basic Constraints: critical
   *    CA:FALSE
   */
  public static final String TEST_CERT_WITH_INVALID_ORGANIZATION_UNIT_PREFIX =
      "-----BEGIN CERTIFICATE-----\n"
          + "MIIDXjCCAkagAwIBAgIUf0A6ygebPHdmubKEJHEelx4e/SMwDQYJKoZIhvcNAQEL\n"
          + "BQAwYDEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTEtMCsGA1UECwwkYjY3NDQ2\n"
          + "ZTUtYjJiMC00NjQ4LWEwZDAtNzcyZDNkMzk5ZGNiMRQwEgYDVQQHDAtleGFtcGxl\n"
          + "dG93bjAeFw0xNzAzMjkyMDM1NTRaFw0yNzAzMjcyMDM1NTRaMGAxGTAXBgNVBAMM\n"
          + "EHRlc3QuZXhhbXBsZS5jb20xLTArBgNVBAsMJGI2NzQ0NmU1LWIyYjAtNDY0OC1h\n"
          + "MGQwLTc3MmQzZDM5OWRjYjEUMBIGA1UEBwwLZXhhbXBsZXRvd24wggEiMA0GCSqG\n"
          + "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKKmO/4dYA19ETDA5sCl1Ai9QZ5vtyljnT\n"
          + "gPW+w/4KIx6pJ+3pEdfnh5D7SEgWqWvK9/TUh37/6gIdMIMMCNPVIV8hN4oL7AAj\n"
          + "NLdqJJR9KtwvWiHzr/2VHrwRtYReJJ2MoUKhDvz3aRykJxFL4kVoCHtKpkTyVFtK\n"
          + "WOTKoRgBvF9hz0nUe27sHABy4hRafuLXM+gG5cwTuXTRYg3mXhLN6V9e6hV1cS4C\n"
          + "cRp10N+ncE+9FmO1i0jjSv4F1d4/nE6dNicJqhpfqJhIwVCp+W+VAYyOhOiel1ae\n"
          + "BJBx6ju5Qvwp8X5l1BXTNdHU5c93llNttaFOh9bvIA0MlVWMy4t/AgMBAAGjEDAO\n"
          + "MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAAPMSsGhCP18oEiteTDO\n"
          + "rFXgoXdlQi8zZuynn5cEAVgWyqV7repy3XRoq7A7n3Y7vUDNDpKixBHp15wXAP93\n"
          + "edrwfoPFowZVXEicdMjlqhf62esa/A0gNo6vQvBIsos/OZZxhpY8kxskdlKAPY4v\n"
          + "XAHiXsOKw767M9qDeBA3SFSrEL4YMfdhoMoUZr/ayK1Y/j8xPn0CL33rNWkv7SoX\n"
          + "jnfmsSqWxhg/t/mIjvCR3EfOfpSHpPE4tCCEKD2TvrRxrZO2UBOZ+Y1mc6L33GGV\n"
          + "fpgSc+FTem/FObrbCUDruX3hCVTQY3Gn1YiSvblPRay29eeR4JeIyPYnzWW06zN8\n"
          + "IMg=\n"
          + "-----END CERTIFICATE-----";

  /**
   * Version: 3 (0x2)
   * Signature Algorithm: sha256WithRSAEncryption
   * Issuer: CN=test.example.com, L=exampletown
   * Validity
   *    Not Before: Mar 28 23:36:57 2017 GMT
   *    Not After : Mar 26 23:36:57 2027 GMT
   * Subject: CN=test.example.com, L=exampletown
   * Subject Public Key Info:
   * Public Key Algorithm: rsaEncryption
   * RSA Public Key: (2048 bit)
   * X509v3 extensions:
   *    X509v3 Basic Constraints: critical
   *    CA:FALSE
   */
  public static final String TEST_CERT_WITHOUT_ORGANIZATION_UNIT = "-----BEGIN CERTIFICATE-----\n"
      + "MIIDADCCAeigAwIBAgIUEkUiS0BpLu5eITSbvH3g8HjYplEwDQYJKoZIhvcNAQEL\n"
      + "BQAwMTEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTEUMBIGA1UEBwwLZXhhbXBs\n"
      + "ZXRvd24wHhcNMTcwMzI4MjMzNjU3WhcNMjcwMzI2MjMzNjU3WjAxMRkwFwYDVQQD\n"
      + "DBB0ZXN0LmV4YW1wbGUuY29tMRQwEgYDVQQHDAtleGFtcGxldG93bjCCASIwDQYJ\n"
      + "KoZIhvcNAQEBBQADggEPADCCAQoCggEBANViOGj5z5ExS1e0BsBJ0HObG9u6c2Bx\n"
      + "VgDGTNS7UeeN9mBjI7XCvMy/en1awqTayVJeA2QPWZKnPahjvC+02/VSOizBy1Vp\n"
      + "PTeM9cetdO94dKadYQqMbMn2163Z1F/kPLjL/8FcBpl+FmrB4rPl/+Oo1TjoUvXp\n"
      + "z/Ys2625RnC4sNlNs0B2Yq3xXg4ysdvS2rD4n8Q4LHKPugkdcRRel0WqPNuMbkGY\n"
      + "IXJNc7zD8CngO7KI8TGsjPkkwSdVdyihAc/DuZRNqdm7YH4KEUeTPHlQVrjxFlR6\n"
      + "1xHATn0q4gTwRMmqqYb9Vs1HMhWz1TFaDQAbZplkapW7fcbnGXwF1o0CAwEAAaMQ\n"
      + "MA4wDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAdyHwsKBuCGjRc/2i\n"
      + "I/vrNTZrn0GYUCH8zdFxs0c/h59feYM6SWjm9iBIIFxxtGP/F/xxLeblNHDPeTdp\n"
      + "O5CTU1c+mfjaExXIxJXdzKA7IyfCljc0G1tANGqL/P12/POExiDBaIBWwu+AC2ED\n"
      + "VPx5tsfOxNxQB1axMaDIGHeJ+SB2/3FhY6VcD6DoCY6TwpJ0mwGP6sgQhJr3qCbE\n"
      + "P/3asUqyGfS5qkFmvwTytnydR/69RZquVJn9m6ZWeOaEekJ7tTy3AiDKN+OYYpzT\n"
      + "ZC7Tw5ZqvuWhXUIkFmAqkTW2CFI8zqSbpLjTHvjxP14Ck9zSuV4oojhvtfjA/wOz\n"
      + "mAeI1w==\n"
      + "-----END CERTIFICATE-----";

  /**
   * This cert appears to be self-signed (Issuer DN == Subject DN) but is actually
   * signed with a CA of the same name.

   * Version: 3 (0x2)
   * Signature Algorithm: sha256WithRSAEncryption
   * Issuer: CN=trickster
   * Validity
   *     Not Before: Feb  7 19:41:38 2017 GMT
   *     Not After : Feb  7 19:41:38 2018 GMT
   * Subject: CN=trickster
   * X509v3 Basic Constraints: critical
   *    CA:FALSE
   */
  public static final String MISLEADING_CERT = "-----BEGIN CERTIFICATE-----\n"
      + "MIICxjCCAa6gAwIBAgIUdYAQkigXgqz1FFN0Qi2T6k2dYJswDQYJKoZIhvcNAQEL\n"
      + "BQAwFDESMBAGA1UEAwwJdHJpY2tzdGVyMB4XDTE3MDIwNzE5NDEzOFoXDTE4MDIw\n"
      + "NzE5NDEzOFowFDESMBAGA1UEAwwJdHJpY2tzdGVyMIIBIjANBgkqhkiG9w0BAQEF\n"
      + "AAOCAQ8AMIIBCgKCAQEAz9r5xtR3Iy/A9mooCA+NjetzqbN4hzzj5ZcJlE/x6UGg\n"
      + "CF393EtOfOUkimDKRgdMFXUnFLBskns9TtmmuQfcGmNV5FDwQpBX2brJbEcOOE3q\n"
      + "dJgV7HDeu1bX+ZpPm0wOwtQXyxr72j03Lt6V+Htrgana3qcejGq8syRO5FEruCsj\n"
      + "vRGlWXd3CYF7/UlVhlc06ILqD+CoePArPrussxAqt4UoUSuoJeaqEvGyi8IJ4mqu\n"
      + "pqUAvWsh8u79A+T+om3JHA7RFhV2Vu83dj+CwMfMsdDiyiaRz5wyVTDpu7X2AeGi\n"
      + "Y3uuJAm/nc6qyDmuAo6BhnFux6dLLlCJ0EqyEzjAQwIDAQABoxAwDjAMBgNVHRMB\n"
      + "Af8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQDPa6O7GIdyQOwUWYYuf7ed8Qj28Jy7\n"
      + "K8utG7SBmE6iPt978m1VW3u01YMh61yNOcs9RBGE7I2H28Zuu9ut4MY8BNBV00rE\n"
      + "sAaPHeOQmEGPPt5oZ1ztlAjSOK9YHOfHaKj4ISfMdhDQ4vAOxGbj3NJMsxiYL4oH\n"
      + "4yQp0lZ5S1TVNZXn77sr5HXuzy+2r40HDc/4Q/9iQseB6Aypjii1Q6m8eej6rcnC\n"
      + "snC8luPGbSwo31gKr9wFxv78GJcswIGt6fi4CxV7eGWn0p9EY4NsR8jdatLd/eKD\n"
      + "qA2eKfjSi415xgI1eOf89HvoYKlBGYuFxXB3YRkJfpS+khFeu7HTsyj2\n"
      + "-----END CERTIFICATE-----";

  /**
   *  Version: 3 (0x2)
   *  Serial Number:
   *      14:7b:69:d1:56:80:9b:07:26:f6:0e:03:0a:1f:7a:ed:96:12:be:c2
   *  Signature Algorithm: sha256WithRSAEncryption
   *  Issuer: CN=foo.com
   *      Validity
   *  Not Before: Feb 10 22:38:59 2017 GMT
   *  Not After : Feb 10 22:38:59 2018 GMT
   *  Subject: CN=foo.com
   *  X509v3 extensions:
   *  X509v3 Basic Constraints: critical
   *  CA:TRUE
   */
  public static final String SELF_SIGNED_CA_CERT = "-----BEGIN CERTIFICATE-----\n"
      + "MIICxTCCAa2gAwIBAgIUFHtp0VaAmwcm9g4DCh967ZYSvsIwDQYJKoZIhvcNAQEL\n"
      + "BQAwEjEQMA4GA1UEAwwHZm9vLmNvbTAeFw0xNzAyMTAyMjM4NTlaFw0xODAyMTAy\n"
      + "MjM4NTlaMBIxEDAOBgNVBAMMB2Zvby5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IB\n"
      + "DwAwggEKAoIBAQDFxKUdiiwrJ9fmW5iD+jz4Ofi/dH1zX6hzh1yO5AEb0B34BmcX\n"
      + "kFCjdKMidXLFY7tAbpFrZHx/kwldoXN2ee9xro5/mgaTMQgDGdUrtk2Z0laUs05I\n"
      + "fiCLWlUnCvNqIEBXc2c56Qj6dAn/cWAJIw6rH6+gLuenMYr4PGiK0rzQHQ8pAW42\n"
      + "y9XOwPuMVT62z16Qbf9Np5S6sKYIjunFSbCte3MsGyYb9A+BXlCmwgKcMBgUHT+c\n"
      + "cxICkM++yPogju+dNp2RSIIk4Ji5KAxUyT3JjZDb6dyygMjftfvqH+FUYuLIiVYR\n"
      + "UhjmXGRrYm402HZXXXxT+jcHKhAPvHofeJxzAgMBAAGjEzARMA8GA1UdEwEB/wQF\n"
      + "MAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJvRkqdhiX/3fNDKBly3HxIg4ACX+pF4\n"
      + "GmG5NL+WY/o6jMxEyW3BMSx67Jkgzi9BnTw8lTSkil7lXJjG9Homzi/HJuFsceH2\n"
      + "lMtAOlLxsvczA90jyp0qGdy7L7hrKPvSGZ2vUehaTIjdcteL6c7GwlotSA7w6G8i\n"
      + "Xj//23SsjYge8IalqnFonYG8u9q0u7N0U0G9C6Rdo5WzCAIuzRBkT8ka0ZAaTgSV\n"
      + "iSIanWI+olDxF/IRhnRCU1HmvAImyvDd7CEjI0Y+HSXqZfc+c1RvfbtoR9fS4n/v\n"
      + "6qAlCDS+r+SU+v19UsFW8cC31UyWQwrpaAMYPYhwqK1Z4nPN+AgAGGY=\n"
      + "-----END CERTIFICATE-----";

  /**
   //.
   Version: 3 (0x2)
   Serial Number:
   12:65:5e:4c:79:5e:9c:ac:81:b8:34:1d:98:68:ca:52:d3:47:e5:ed
   Signature Algorithm: sha256WithRSAEncryption
   Issuer: CN=bar
   Validity
   Not Before: Feb 13 20:21:34 2017 GMT
   Not After : Feb 13 20:21:34 2018 GMT
   Subject: CN=bar
   */
  public static final String V3_CERT_WITHOUT_BASIC_CONSTRAINTS = "-----BEGIN CERTIFICATE-----\n"
      + "MIICqDCCAZCgAwIBAgIUEmVeTHlenKyBuDQdmGjKUtNH5e0wDQYJKoZIhvcNAQEL\n"
      + "BQAwDjEMMAoGA1UEAwwDYmFyMB4XDTE3MDIxMzIwMjEzNFoXDTE4MDIxMzIwMjEz\n"
      + "NFowDjEMMAoGA1UEAwwDYmFyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n"
      + "AQEA5liBEeqqjTWcofS3tz4xm4CST1vYgoEt2CTEf16iKHiiirK9NIRX+OB5U6nW\n"
      + "6rXP8q7PUQ6DmbDfmjNFvWrKxuuPhcDY4M+g++pJ7VZ46E00e3yNqYoAJv/8pFfz\n"
      + "yhLc/CYF7JgfIh3fPv6gjY2Q8Asi1fIzgv17LaP7NJtFTxzPzg9hxHhHZY8OyMnm\n"
      + "/+LhXd4SPETctNndMfp97g9z2epf/sYLQMUcoq/CJQf4ilNkeK07E6om9JkGxOLl\n"
      + "6mWLCIHyx2FXLIvSPE+zvCHeK+6PDX0RarBSKRNntH+7aNlo3k7VOHZYM6Xj6qmE\n"
      + "mOyWHxUlHgVy4myY5vqd8R7+PwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAgH22O\n"
      + "1Tn4xeVvl5fdBR77Ywr+lSLxpZUcOm2XP4WJd5a5xzZvqC9SdhFADWEeGBXc4pG3\n"
      + "12Wmp8y/9mmOu4Yc708UCL9aimKnl4+sX9fkZnnbQrIc/bODdi3B0I+17Irn6aAe\n"
      + "0mXEok5kYMFOk77ZZF3OG8bUojHGINKvW1bamMEqL4F4VU1WIfgBgDf4F1MdbCAZ\n"
      + "KtCY6DlUwxcFDWrktx1XGFZC5PSedBHWYcx0bsV+lllCfEm48PXqUnIOjpjsbVg1\n"
      + "+NHBdPGyKlnRkvI4xIodUXfn7FrS3KWL8k9NzL5FGXCvzXoGZKBvcJuu0/2XXl+3\n"
      + "Jykws+qOGWF351JZ\n"
      + "-----END CERTIFICATE-----";

  /**
   *
   *  Version: 3 (0x2)
   Serial Number:
   c7:0b:53:ea:27:6e:9f:26
   Signature Algorithm: sha1WithRSAEncryption
   Issuer: C=US, ST=NY, O=Test Org, OU=app:a12345e5-b2b0-4648-a0d0-772d3d399dcb,
   CN=example.com/emailAddress=test@example.com
   Validity
   Not Before: Mar 30 18:34:52 2017 GMT
   Not After : Mar 30 18:34:52 2018 GMT
   Subject: C=US, ST=NY, O=Test Org, OU=app:a12345e5-b2b0-4648-a0d0-772d3d399dcb,
   CN=example.com/emailAddress=test@example.com
   X509v3 extensions:
   X509v3 Subject Key Identifier:
   01:69:9A:20:83:EB:49:5D:7C:16:68:A0:7F:B9:D6:A5:D4:5B:FC:06
   X509v3 Authority Key Identifier:
   keyid:01:69:9A:20:83:EB:49:5D:7C:16:68:A0:7F:B9:D6:A5:D4:5B:FC:06

   X509v3 Key Usage:
   Digital Signature, Key Encipherment
   X509v3 Extended Key Usage:
   TLS Web Client Authentication
   */
  public static final String SELF_SIGNED_CERT_WITH_CLIENT_AUTH_EXT = "-----BEGIN CERTIFICATE-----\n"
      + "MIIDEjCCAnugAwIBAgIJAMcLU+onbp8mMA0GCSqGSIb3DQEBBQUAMIGXMQswCQYD\n"
      + "VQQGEwJVUzELMAkGA1UECAwCTlkxETAPBgNVBAoMCFRlc3QgT3JnMTEwLwYDVQQL\n"
      + "DChhcHA6YTEyMzQ1ZTUtYjJiMC00NjQ4LWEwZDAtNzcyZDNkMzk5ZGNiMRQwEgYD\n"
      + "VQQDDAtleGFtcGxlLmNvbTEfMB0GCSqGSIb3DQEJARYQdGVzdEBleGFtcGxlLmNv\n"
      + "bTAeFw0xNzAzMzAxODM0NTJaFw0xODAzMzAxODM0NTJaMIGXMQswCQYDVQQGEwJV\n"
      + "UzELMAkGA1UECAwCTlkxETAPBgNVBAoMCFRlc3QgT3JnMTEwLwYDVQQLDChhcHA6\n"
      + "YTEyMzQ1ZTUtYjJiMC00NjQ4LWEwZDAtNzcyZDNkMzk5ZGNiMRQwEgYDVQQDDAtl\n"
      + "eGFtcGxlLmNvbTEfMB0GCSqGSIb3DQEJARYQdGVzdEBleGFtcGxlLmNvbTCBnzAN\n"
      + "BgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAtyHjDd5AYxUr0KFvlyeiDysyFuzoIW5y\n"
      + "9AS8LblFEsYwfVF7MU8kQ4O0HzosWbCv72U6vYBz0vmolcK5F/4LBbgqCFZQRrFV\n"
      + "jzkW60ertb2te3OHeRuxKYcA7EE4UosXulQ/3lJmS1XHBPtZOJRdelTLoHyUZ37y\n"
      + "BUa6ZkGvi90CAwEAAaNkMGIwHQYDVR0OBBYEFAFpmiCD60ldfBZooH+51qXUW/wG\n"
      + "MB8GA1UdIwQYMBaAFAFpmiCD60ldfBZooH+51qXUW/wGMAsGA1UdDwQEAwIFoDAT\n"
      + "BgNVHSUEDDAKBggrBgEFBQcDAjANBgkqhkiG9w0BAQUFAAOBgQAg6sfi3lMbWMUY\n"
      + "ObbubrWB2pPWo7W6GCsem2M0Qri8RuMUqzHNvatUnaIuD9yatdP+vDuFdGbX3PTF\n"
      + "wjh44yBrxcRGcYFdzBOIos+i5MMtDWorJY/0IH8mVEd3ckMcfVgMVP25ZvlYjhdY\n"
      + "dCNw/Rku+LafRQJOlSBZqy7K7qtzbA==\n"
      + "-----END CERTIFICATE-----";

  /**
   * Version: 3 (0x2)
   Serial Number:
   fb:bd:39:9b:59:d5:98:4d
   Signature Algorithm: sha1WithRSAEncryption
   Issuer: C=US, ST=NY, O=Test Org, OU=app:a12345e5-b2b0-4648-a0d0-772d3d399dcb,
   CN=example.com/emailAddress=test@example.com
   Validity
   Not Before: Mar 30 19:04:56 2017 GMT
   Not After : Mar 30 19:04:56 2018 GMT
   Subject: C=US, ST=NY, O=Test Org, OU=app:a12345e5-b2b0-4648-a0d0-772d3d399dcb,
   CN=example.com/emailAddress=test@example.com
   X509v3 extensions:
   X509v3 Subject Key Identifier:
   2B:77:1B:63:E2:92:6B:29:9D:31:D4:0E:E0:79:0D:5F:61:E9:77:1A
   X509v3 Authority Key Identifier:
   keyid:2B:77:1B:63:E2:92:6B:29:9D:31:D4:0E:E0:79:0D:5F:61:E9:77:1A
   */
  public static final String SELF_SIGNED_CERT_WITH_NO_CLIENT_AUTH_EXT = "-----BEGIN CERTIFICATE-----\n"
      + "MIIC8DCCAlmgAwIBAgIJAPu9OZtZ1ZhNMA0GCSqGSIb3DQEBBQUAMIGXMQswCQYD\n"
      + "VQQGEwJVUzELMAkGA1UECAwCTlkxETAPBgNVBAoMCFRlc3QgT3JnMTEwLwYDVQQL\n"
      + "DChhcHA6YTEyMzQ1ZTUtYjJiMC00NjQ4LWEwZDAtNzcyZDNkMzk5ZGNiMRQwEgYD\n"
      + "VQQDDAtleGFtcGxlLmNvbTEfMB0GCSqGSIb3DQEJARYQdGVzdEBleGFtcGxlLmNv\n"
      + "bTAeFw0xNzAzMzAxOTA0NTZaFw0xODAzMzAxOTA0NTZaMIGXMQswCQYDVQQGEwJV\n"
      + "UzELMAkGA1UECAwCTlkxETAPBgNVBAoMCFRlc3QgT3JnMTEwLwYDVQQLDChhcHA6\n"
      + "YTEyMzQ1ZTUtYjJiMC00NjQ4LWEwZDAtNzcyZDNkMzk5ZGNiMRQwEgYDVQQDDAtl\n"
      + "eGFtcGxlLmNvbTEfMB0GCSqGSIb3DQEJARYQdGVzdEBleGFtcGxlLmNvbTCBnzAN\n"
      + "BgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAwnMy7/SfQIzPe+9GJujQVHb2OP5dOMvz\n"
      + "LSQLBwJtHdzv2xtnDL+vFB4F1Cv6NeTbhnWi89ebyOqGgqyeX7wga8UN9Pmih16Q\n"
      + "/i8Bx//+TJjUqj1umhGZmGL4sWx8NwrP9QiuvrNf/sdq0ilbclWgn5UBuiAKty48\n"
      + "BjaEpEGf0AMCAwEAAaNCMEAwHQYDVR0OBBYEFCt3G2PikmspnTHUDuB5DV9h6Xca\n"
      + "MB8GA1UdIwQYMBaAFCt3G2PikmspnTHUDuB5DV9h6XcaMA0GCSqGSIb3DQEBBQUA\n"
      + "A4GBAJ9SipBB/J17usRtaDp59iIlTiyF1N14Qw1XuR0ZpVGXCx5r46DQVHQIdno+\n"
      + "EPa2sOCml5CIOlNko6Edr0GlWOWkhZyTyZTW6oHaDxVQXrhbVemmKOUY0LM9r2l+\n"
      + "TqtBv192PPCKbrJChCVmrDltpc5F5TeyTAWn/ElIVz6Za+y/\n"
      + "-----END CERTIFICATE-----";

  /**
   * Version: 3 (0x2)
   Serial Number: 1 (0x1)
   Signature Algorithm: sha256WithRSAEncryption
   Issuer: CN=testCa
   Validity
   Not Before: Sep 21 17:24:09 2017 GMT
   Not After : Sep 21 17:24:15 2027 GMT
   Subject: CN=testCa
   Subject Public Key Info:
   Public Key Algorithm: rsaEncryption
   X509v3 extensions:
   X509v3 Key Usage: critical
   Certificate Sign, CRL Sign
   X509v3 Basic Constraints: critical
   CA:TRUE, pathlen:0
   X509v3 Subject Key Identifier:
   B2:23:50:C6:8F:7F:B4:5F:62:1A:AD:00:91:35:FA:91:A3:BD:9E:5A
   */
  public static final String CERTSTRAP_GENERATED_CA_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n"
      + "MIIE4jCCAsqgAwIBAgIBATANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDEwZ0ZXN0\n"
      + "Q2EwHhcNMTcwOTIxMTcyNDA5WhcNMjcwOTIxMTcyNDE1WjARMQ8wDQYDVQQDEwZ0\n"
      + "ZXN0Q2EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDYMdo2q+GvAPn2\n"
      + "kUm82ZMLMJjOVpYHv2/G7f9gBuTHb1Z9uJcnH3rUTIh0JNNAz+/IuuRxBJb5rWFW\n"
      + "K4Dp1vINRG7ltcDQXQkS1mPigt/5rSHWv3+WSZ4tZmMw6JUxDjQ+kqO9sjDkGm4Y\n"
      + "MG4Qkmmo7hjAKei+rv1beN8m6wNSBTfDKtsZZZeXe7Ru9bHCzo/1f4Q2XZ5OYoOk\n"
      + "4gznM2JRwbbhbcpRX36QuFzSUXSMcXSaCR6WfC/1R78lz5IqdjRLTLSJe7tSh7JV\n"
      + "5ZRr6UiGvcdS0DWXXG7Ers36FfSeaJUX3LLwMy2AKcsbLcou0GzY+Mt7QqK2XH6y\n"
      + "NydxqqNtDz5wZu0117DtWBLYZP/OxUySyh5rA9JrryuSCE9SD98Mrno0Ho1OqC/P\n"
      + "3rwXdoShKHmLSbsT7wo85xOi9iBsJHpG69uK9EPz8WuuUguczVoOA8L4NQ/11Imv\n"
      + "/ZliomfhICojZihnK0DhH/WBr4xgYUVc0wfJ7zAgOUmQ+pUrzNjTmTzV/zWKsT2R\n"
      + "t+s66kxJfoqNGKRfP//YVRZrlThFph8Px4Y+ZZ49f3wucANT9Pa5A4Yx+mLdSW2d\n"
      + "13YYEWwHDWobM67T+u+ttsMBpBfa86i6oVMORnneEOw9UCsiM7hvrBnZEFS0l5dI\n"
      + "2hP1ZWTp8EMkdtCFGDB1ek5SXYz4DwIDAQABo0UwQzAOBgNVHQ8BAf8EBAMCAQYw\n"
      + "EgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUsiNQxo9/tF9iGq0AkTX6kaO9\n"
      + "nlowDQYJKoZIhvcNAQELBQADggIBAEIMx9YXZhBHwsUaRyXmNV0vWty1UReboYLh\n"
      + "XXf4i273hiBFNP0bWBLE0UCJlKm8QzZ6DtgG4sp0Su+oQfMOR3OArSc8lIPOXIkh\n"
      + "MtgwsWyhLPsjkEk0B+AG0RT8LZHSzYuIQhF0sRbE1nIeIHNRjQp+jHIv8HsZI45B\n"
      + "rh3O1PKi8D2Er12omrY0pfDug7u0D0vGdfPygeXVg3aoNTwMu4P37wfcRNgtazdg\n"
      + "Y2oFEw7U6bs8qHz9CyfjSgcuUs3utOqKhCQpOUEzRdsvsgT5EVss1eaYr9SfSiZQ\n"
      + "k/Vmy1XRqLOuhHcZdsnOMmK8WxIIyDDlq0xouHezLQhA1lXvOFmlnDtl4cMQBVuv\n"
      + "MqZgst1ItyGKxJa9Pxnjpyz+T/w3i6ljb46HxLitUSc8jTYXO/LlPWX8MbFPRuZZ\n"
      + "BvgY8wdes1vrz3wGkm5mJ6LMzmSuvXhmIzaqvGNEwBdOLiOhW/QOFPIwD2jNONnq\n"
      + "FQp8lD0jLLfZG5U+G8gb9nbaxDovmJixRje6q8qN9dLQeVyCi52SNJr9rtqPhdm1\n"
      + "RI+RRCbIKBJrLRLP16fTj1f0bM3+TH2OoS5hPR1LTnYNYyDJxwE2+o1mtmKyccN1\n"
      + "7vzbwOrOcyPZ5WBEBG1H1vfMTrAefklycBWxRK/ZtpfH5cZDjBxP7x26I2LY5/ws\n"
      + "fvToHltS\n"
      + "-----END CERTIFICATE-----\n";

  public static final String CERTSTRAP_GENERATED_CA_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\n"
      + "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\n"
      + "-----END RSA PRIVATE KEY-----\n";
}
