package io.pivotal.security.util;

public class CertificateStringConstants {

  /**
   * .
   * openssl x509 -in <(pbpaste) -text -noout:
   * <pp>
   * Subject Name: O=test-org,ST=Jupiter,C=MilkyWay,CN=test-common-name,OU=test-org-unit,L=Europa
   * Duration: 30 days
   * Key Length: 4096
   * Alternative Names: SolarSystem
   * Extended Key Usage: server_auth, client_auth
   * Key Usage: digital_signature
   * Issuer: CN=foo
   * </pp>
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
   * Serial Number:
   * Issuer: CN=foo.example.com
   * Validity
   * Not Before: Feb  6 20:00:27 2017 GMT
   * Not After : Feb  6 20:00:27 2018 GMT
   * Subject: CN=foo.example.com
   * Subject Public Key Info:
   * Public Key Algorithm: rsaEncryption
   * RSA Public Key: (2048 bit)
   * X509v3 extensions:
   * X509v3 Basic Constraints: critical
   * CA:FALSE
   */
  public static final String SIMPLE_SELF_SIGNED_TEST_CERT = "-----BEGIN CERTIFICATE-----\n"
      + "MIIC0jCCAbqgAwIBAgIUW6HcroJaHBMF2VK/6z13iBnNxeAwDQYJKoZIhvcNAQEL\n"
      + "BQAwGjEYMBYGA1UEAwwPZm9vLmV4YW1wbGUuY29tMB4XDTE3MDIwNjIwMDAyN1oX\n"
      + "DTE4MDIwNjIwMDAyN1owGjEYMBYGA1UEAwwPZm9vLmV4YW1wbGUuY29tMIIBIjAN\n"
      + "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyy+c0ZPNPmGBzkiC+XzMJkbgJFK7\n"
      + "2BNgLpzI1AmqFBMBs7dSfxypS7qTfAEUQ1HMY2S9/odhslEUIyBVPguonk++WvGw\n"
      + "w6P49d3GPK6beyrw+FobBkVWJ64qRZIUJlRanFzs1yGnRJ2omHgJ03sTYiL4t8wt\n"
      + "Cm9po3gp7QwGXQ2Ol1QEadH095WBdwkN0Wo7WF/4+Fz7cACCBZNQoSYmT3uREH9S\n"
      + "iVur6H4WLsPEs5QBV+o9204qVZh0er+/LEwzuqZD97gppLVdYk673R2Kje4Gc6mz\n"
      + "Y61oKlQzSQXPsA1Sx7dOUgMGtzhRrFgUE1WzvTqiDVQB9dEsn1JILJWA7wIDAQAB\n"
      + "oxAwDjAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQANE8zWwdjCEmOw\n"
      + "+wbqVR3RyL1P2T0eQI1ML/epxVNLRoAKihs2ypKFLpLC9P7mucsHxl4FY/pzXOJo\n"
      + "i0PEG/ZCapRunC3XVwxGUZos2ytPIebyshlp4eRTyuch7ei3aTO2cLrLsgWZxyxc\n"
      + "i5JveF8PvPZkOR5qzq6P7dMpQde3nL8/kLRwp7aSE8OAKoeyhEDCy+e9lPh9+Q/g\n"
      + "36dvhRfyD3PUifLC1A6usOedplxEJpf5hNlyVljTXRZXRijltHIxsp2vf8vzSLO4\n"
      + "zam9Ke7B5YU8lRd5PlyFXDp+vEJ4HaX8FMtUthLvvDQ7l9UOR7r2rf3hfggxC7/s\n"
      + "s2smQYqB\n"
      + "-----END CERTIFICATE-----";

  /**
   * This cert appears to be self-signed (Issuer DN == Subject DN) but is actually
   * signed with a CA of the same name.
   * <pp>
   * Version: 3 (0x2)
   * Signature Algorithm: sha256WithRSAEncryption
   * Issuer: CN=trickster
   * Validity
   * Not Before: Feb  7 19:41:38 2017 GMT
   * Not After : Feb  7 19:41:38 2018 GMT
   * Subject: CN=trickster
   * X509v3 Basic Constraints: critical
   * CA:FALSE
   * </pp>
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
   * Version: 3 (0x2)
   * Serial Number:
   * 14:7b:69:d1:56:80:9b:07:26:f6:0e:03:0a:1f:7a:ed:96:12:be:c2
   * Signature Algorithm: sha256WithRSAEncryption
   * Issuer: CN=foo.com
   * Validity
   * Not Before: Feb 10 22:38:59 2017 GMT
   * Not After : Feb 10 22:38:59 2018 GMT
   * Subject: CN=foo.com
   * X509v3 extensions:
   * X509v3 Basic Constraints: critical
   * CA:TRUE
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
   * .
   * Version: 3 (0x2)
   * Serial Number:
   * 12:65:5e:4c:79:5e:9c:ac:81:b8:34:1d:98:68:ca:52:d3:47:e5:ed
   * Signature Algorithm: sha256WithRSAEncryption
   * Issuer: CN=bar
   * Validity
   * Not Before: Feb 13 20:21:34 2017 GMT
   * Not After : Feb 13 20:21:34 2018 GMT
   * Subject: CN=bar
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
}
