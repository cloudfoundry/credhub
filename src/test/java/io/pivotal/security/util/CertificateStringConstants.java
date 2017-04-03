package io.pivotal.security.util;

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
}
