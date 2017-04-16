package io.pivotal.security.util;

public class TestConstants {

  // generate with ./build/credhub n -t ssh -n foo -k 4096
  public static String SSH_PUBLIC_KEY_4096 =
      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDs8lQIdJ+tnc9jufX9wLzCPVS1utoTJ"
          + "wzQO2NS5F07OEWXnR94XtYY3KtBLu10LHjZzH5maxdWYkyb4GgYSwV+6ln+Txn7"
          + "9LQT8gStbK+mJBFWnGplHNU+loHdHkKckOVihBgDfjsW58s46X9HmKAiUetXBaz"
          + "QX2pVOhOKBETgEstVKB1CoN0fP98mbergW+THHxDpbtodep1EoWZePn/Qe/jly7"
          + "joL8HZuVAwzunmBsrrm0B1cRF3mG4/XZDdHqbz1humoz/8V8KMBuC899XhN1yZv"
          + "mdZqe3OhpENr8O3e26p7xxTyCyOs5kk2Myv7YqWOyr43obFIzGUcLLMj3p1SDuk"
          + "gzpxCHPmiZ72zO/hZ+HkB6319iZPsZgrR8vapQsJY5MfYJO9KPj0BKlFdi9y578"
          + "VCj1pw6OYz7fuRrSfu/W0S1l9FLI450aFsNSji5ZX7elJ5A0qDQaFblECAsmbMj"
          + "T9MCDyJDjZfmtb9UY4j/ywFeYP26RLqbdWMZBYgukVg+isCyxJczecaJKRWBnUr"
          + "yz5sSvbsOC38rdu7LAl/vxf8m2ZY6d/TZ2SgTEDgD4YxOG6WZEm2z2JGpgGtQcV"
          + "O4ulfSa/xqovvidLc/kTWR15dVts+r1Uv7Btaax7XqTKqBkrxjhbpXD2RVQAeZh"
          + "BOQ80pPbFtvUPN1pAdgc14w==";
  public static String SSH_PUBLIC_KEY_4096_WITH_COMMENT =
      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDs8lQIdJ+tnc9jufX9wLzCPVS1utoTJ"
          + "wzQO2NS5F07OEWXnR94XtYY3KtBLu10LHjZzH5maxdWYkyb4GgYSwV+6ln+Txn7"
          + "9LQT8gStbK+mJBFWnGplHNU+loHdHkKckOVihBgDfjsW58s46X9HmKAiUetXBaz"
          + "QX2pVOhOKBETgEstVKB1CoN0fP98mbergW+THHxDpbtodep1EoWZePn/Qe/jly7"
          + "joL8HZuVAwzunmBsrrm0B1cRF3mG4/XZDdHqbz1humoz/8V8KMBuC899XhN1yZv"
          + "mdZqe3OhpENr8O3e26p7xxTyCyOs5kk2Myv7YqWOyr43obFIzGUcLLMj3p1SDuk"
          + "gzpxCHPmiZ72zO/hZ+HkB6319iZPsZgrR8vapQsJY5MfYJO9KPj0BKlFdi9y578"
          + "VCj1pw6OYz7fuRrSfu/W0S1l9FLI450aFsNSji5ZX7elJ5A0qDQaFblECAsmbMj"
          + "T9MCDyJDjZfmtb9UY4j/ywFeYP26RLqbdWMZBYgukVg+isCyxJczecaJKRWBnUr"
          + "yz5sSvbsOC38rdu7LAl/vxf8m2ZY6d/TZ2SgTEDgD4YxOG6WZEm2z2JGpgGtQcV"
          + "O4ulfSa/xqovvidLc/kTWR15dVts+r1Uv7Btaax7XqTKqBkrxjhbpXD2RVQAeZh"
          + "BOQ80pPbFtvUPN1pAdgc14w== dan@foo";
  public static String RSA_PUBLIC_KEY_4096 = "-----BEGIN PUBLIC KEY-----\n"
      + "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA7PJUCHSfrZ3PY7n1/cC8\n"
      + "wj1UtbraEycM0DtjUuRdOzhFl50feF7WGNyrQS7tdCx42cx+ZmsXVmJMm+BoGEsF\n"
      + "fupZ/k8Z+/S0E/IErWyvpiQRVpxqZRzVPpaB3R5CnJDlYoQYA347FufLOOl/R5ig\n"
      + "IlHrVwWs0F9qVToTigRE4BLLVSgdQqDdHz/fJm3q4Fvkxx8Q6W7aHXqdRKFmXj5/\n"
      + "0Hv45cu46C/B2blQMM7p5gbK65tAdXERd5huP12Q3R6m89YbpqM//FfCjAbgvPfV\n"
      + "4Tdcmb5nWantzoaRDa/Dt3tuqe8cU8gsjrOZJNjMr+2Kljsq+N6GxSMxlHCyzI96\n"
      + "dUg7pIM6cQhz5ome9szv4Wfh5Aet9fYmT7GYK0fL2qULCWOTH2CTvSj49ASpRXYv\n"
      + "cue/FQo9acOjmM+37ka0n7v1tEtZfRSyOOdGhbDUo4uWV+3pSeQNKg0GhW5RAgLJ\n"
      + "mzI0/TAg8iQ42X5rW/VGOI/8sBXmD9ukS6m3VjGQWILpFYPorAssSXM3nGiSkVgZ\n"
      + "1K8s+bEr27Dgt/K3buywJf78X/JtmWOnf02dkoExA4A+GMThulmRJts9iRqYBrUH\n"
      + "FTuLpX0mv8aqL74nS3P5E1kdeXVbbPq9VL+wbWmse16kyqgZK8Y4W6Vw9kVUAHmY\n"
      + "QTkPNKT2xbb1DzdaQHYHNeMCAwEAAQ==\n"
      + "-----END PUBLIC KEY-----";
  public static String PRIVATE_KEY_4096 = "-----BEGIN RSA PRIVATE KEY-----fake\n"
      + "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\n"
      + "-----END RSA PRIVATE KEY-----";
  public static String TEST_CA = "-----BEGIN CERTIFICATE-----\n" +
      "MIIC2jCCAcKgAwIBAgIUFgNChBoe9Kx/eOSuuNZi2yvc+JswDQYJKoZIhvcNAQEL\n" +
      "BQAwDTELMAkGA1UEAwwCY2EwHhcNMTcwNDE2MjEyMjI1WhcNMTgwNDE2MjEyMjI1\n" +
      "WjANMQswCQYDVQQDDAJjYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n" +
      "ANGFpkI3QTOp+1nc4r3EQUIO1F2xXTLMV3OQihB4hWdR2wp5I2p4zJWrlkla0ov+\n" +
      "Mq0pFLHVST+3eUa9PrY67M5vXl3WaCXmR41oiiwTPmE/atV6sozNlVPYwgRCEitm\n" +
      "nh/B2wBOBTT434jppqFn4l9WjECSc9c/3mlWKssvyX3p6Z4yc0P98wnxx917u5So\n" +
      "M3GaXArEQB8dMP/Rg+zxIv5GRbL5G6otehWxulTl5c0f75PflWSa4XNr4Fs4fhgU\n" +
      "WL/NwwmtZ7gEgIGjZ3YI1eOegaljnOIFtuGVmfV54OJOjem/FamM/uF842i3lYsl\n" +
      "WWrVXMr+VltBmN+Ybat5vjsCAwEAAaMyMDAwHQYDVR0OBBYEFPHvvURzWOKwVAoo\n" +
      "ORItTEa9NI/MMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAE5A\n" +
      "r+UUt4h5+lL/3hwLvPyUqGcE9wFnwlkIR3R0A212WAMkzkGF7LgYnid2YRM0mbWz\n" +
      "HpfYmPWoupWi8HHXmuTCXC6GM/86EUGJhZnYzthb1FsXXEOb87T6/X0Sw9O5BqT9\n" +
      "ML9vHlB51ebabwAWHDPAR36CQbVpIVqMrdgqyrRkvDGAfLr2ZHhuOxfwJLI0kuFy\n" +
      "u9BJgRUBQhIIAXcN8CEN6eyWSVSMXzNDKuE0iwgalUvbM8WgznSm70XY+kc6xae/\n" +
      "AOd6r+iz1g+uHkSJ5xaACtrzVr7VSizmDL+XJiBfBdMK2sEmlNLotlSRP/O+5bjr\n" +
      "Rhw3NVtKOZCerw690oQ=\n" +
      "-----END CERTIFICATE-----";
  public static String TEST_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n" +
      "MIIC4DCCAcigAwIBAgIUPVl084J2G//3jweNVHSH0/BDJdIwDQYJKoZIhvcNAQEL\n" +
      "BQAwDTELMAkGA1UEAwwCY2EwHhcNMTcwNDE2MjEyMjQxWhcNMTgwNDE2MjEyMjQx\n" +
      "WjAWMRQwEgYDVQQDDAtjb21tb24tbmFtZTCCASIwDQYJKoZIhvcNAQEBBQADggEP\n" +
      "ADCCAQoCggEBANqU2FZ6hQdS5izdHHR/ywuFo9eK22SSy5DX6GR6L6HCa+Pf+3FA\n" +
      "rKrnKy0KskCTya0FWRiFmEHTrZJzr502DGIemjTrqGxzUR3TkmLhPUtV58xGbMYw\n" +
      "8YOGi6mWdb1TVNsnNlxOf+4c9CiiVfyYg/nc29t/n2bWKnFiMYGlwNtlTEFsg6H0\n" +
      "ifhRbva+z5FWy6apiuUNCz3Q2oa+yieAzaHml3BCzvJ6nVmB9dsav9Mt9EIU4sdS\n" +
      "/lSdK7QkxNxhg6pRS98upkryXNw5NrTpp/fJ7dYyac6a6G1+P6HaolZhZHpgdVND\n" +
      "A1yW1XoAskgLcZGJLgQ4FCN1sYxl4XFP9QsCAwEAAaMvMC0wHQYDVR0OBBYEFL5t\n" +
      "JWiHqYFS1ZK1tnG3Q3XYS76mMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQAD\n" +
      "ggEBAGErzXfL15i7iweGpncIF2NNwph2k3YLRhqJ4YVs8pbqsogB2dCIpz4QQkvQ\n" +
      "OskZfeai+5l2fbR2PAQWU8CirRb2QBx6VyUOYrd5zXg3git3ANlT6yqebT11loAd\n" +
      "u6S2r0I7hqauSKtGwyzoaUiExBKzdUtqvDrk9LhbPpEuJGaiGp/XgZ/7PZNvWoxy\n" +
      "X3knSvhcyAHtlaGxnvwk7ckjqfm7eNy3gL0aQLrH43aAGipjeP4naJxUPblNbYr6\n" +
      "B43UDIeGibgFA6hWINto/J/g6pH3hCmNswitc+bapd6OLykzOqWEIfQok9qqPiJJ\n" +
      "fzIgh+i2442eQnzGcQHdS2V1fRI=\n" +
      "-----END CERTIFICATE-----";
  public static String TEST_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\n" +
      "MIIEowIBAAKCAQEA2pTYVnqFB1LmLN0cdH/LC4Wj14rbZJLLkNfoZHovocJr49/7\n" +
      "cUCsqucrLQqyQJPJrQVZGIWYQdOtknOvnTYMYh6aNOuobHNRHdOSYuE9S1XnzEZs\n" +
      "xjDxg4aLqZZ1vVNU2yc2XE5/7hz0KKJV/JiD+dzb23+fZtYqcWIxgaXA22VMQWyD\n" +
      "ofSJ+FFu9r7PkVbLpqmK5Q0LPdDahr7KJ4DNoeaXcELO8nqdWYH12xq/0y30QhTi\n" +
      "x1L+VJ0rtCTE3GGDqlFL3y6mSvJc3Dk2tOmn98nt1jJpzprobX4/odqiVmFkemB1\n" +
      "U0MDXJbVegCySAtxkYkuBDgUI3WxjGXhcU/1CwIDAQABAoIBAFtD8uCI36qjLoBl\n" +
      "AlCSW1FAR5zj2Z8wu9aKj/oEGodMCohnKTGsc2wYgaqY4Lyd+INJzF20ylIR9FNG\n" +
      "Anl968W8SV73VqeRrrjpciHfMhyWjeZ5MUm/fdgRAZeZvyeB99hZkxUPodLmO/wL\n" +
      "bCO/+rsFQLdxnjjuC2K0QT+E2fXAnABsuo9XSiwvk2/oJPRvMlyvqYT4MFHkbrxi\n" +
      "D86ncODe2OotIHdNuTKtF/8Uq10WcVDG5OfNBhEBhUCvNsBY+Wc2zGx7CH+UoUj+\n" +
      "MOGcCU4cOhUsR4zokE0z9eRSK6MyaC5s7k1wUWFvRSqq6Z24FVMHbPKoBMFB380Q\n" +
      "0Y91hMECgYEA/faGlmHBpDGSX07Mev0Q0gntXjJu+YcGAolgvNgRtOrA8a3PPHux\n" +
      "IxXzTc26LBrRxAy64cjLHxj/wHaMypBUcTCZCSXpc9a+cmsT/XG+QcnIbeCsBswT\n" +
      "RflJcUzoeS1Bcb8azLSkBOtDRr9qJyMQ7BEI57aVq1s0ZWoSPW8ADVkCgYEA3FWr\n" +
      "L0LzYRW6A0Y+QBqwkAKTxrfqUm8C0f6h25uhi4V9y7IBHNgsrVclBzacBE4HaALU\n" +
      "p9TJrce5gFNeWp+6WrwHVePl/OEgQu2wVsotbhfM9VZGUIM4ltY15lD6iyeSRsWz\n" +
      "yHsCPyDAgSByzayAzGyC0cp2mCVVwcwG8IiDlQMCgYBQrQbWMNnF4iWAd1TH4Sp9\n" +
      "vr+UA+tzAyyqk5+SfgUp9sUyQSerLBP6dFelKKxypFZstCqN3S6Bg3yDVGWnV7Ar\n" +
      "gOesm0mNDfPT/yYLhh2NYp90IEIlqqCYwvdMscTL8c9vZekKjHvqQB5QFDCRnDcc\n" +
      "9tBgY4UqOT/s04RV1bQriQKBgQCJuitFYa5Ms44Q2emznHtdqZ7CCti4Kpgyt95p\n" +
      "LgFu+0TE/UHgy+gxelW1Cpe/wR60D4DqYAKpVD1KT9KdB1cvvHVBZTGwPvExpO4j\n" +
      "ckGvncUKXqGZVk0bTE9o5pmWPmgbQR2+ZdXjrA9pJ+VbV0czgWjMxqgXNs9CUszL\n" +
      "sim+DQKBgHnNHrmvAtEe5AP5WvG+wIwXbyPXV+36oUNaAQjaoavz6clL/ot8N9FE\n" +
      "e3WLDaQwSKyq4jIneUn6fYUOeekDy9a9BNWf6G/e9t9TiSjjLqmCicsWeOwUcgaF\n" +
      "ey2GGVajvSTtRawG8p+wJWlDtmv3vq/19XM6koHwNcI4o3h7dn38\n" +
      "-----END RSA PRIVATE KEY-----";
}
