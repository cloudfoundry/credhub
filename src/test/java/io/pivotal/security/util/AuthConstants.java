package io.pivotal.security.util;

public class AuthConstants {
  // JWT token signed by private key for public key in `application-unit-test.yml`
  // Valid for about 50 years!!!
  public static final String UAA_OAUTH2_TOKEN = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImxlZ2FjeS10b2tlbi1rZX"
      + "kiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiJlYTYxY2VlYzM2Nzk0ZGE5OWVhYTIyMGUwYTNjYTA3ZCIsInN1YiI6ImE1N"
      + "GIxODc0LTJhZWYtNGU3Ny05OTFmLWE5N2Y4ZDExMzJlNyIsInNjb3BlIjpbImNyZWRodWIud3JpdGUiLCJjcmVkaHV"
      + "iLnJlYWQiXSwiY2xpZW50X2lkIjoiY3JlZGh1Yl9jbGkiLCJjaWQiOiJjcmVkaHViX2NsaSIsImF6cCI6ImNyZWRod"
      + "WJfY2xpIiwiZ3JhbnRfdHlwZSI6InBhc3N3b3JkIiwidXNlcl9pZCI6ImE1NGIxODc0LTJhZWYtNGU3Ny05OTFmLWE"
      + "5N2Y4ZDExMzJlNyIsIm9yaWdpbiI6InVhYSIsInVzZXJfbmFtZSI6ImNyZWRodWJfY2xpIiwiZW1haWwiOiJjcmVka"
      + "HViX2NsaSIsImF1dGhfdGltZSI6MTQ4NzcxODM1NiwicmV2X3NpZyI6ImI5MWRjNmQiLCJpYXQiOjE0ODc3MTgzNTY"
      + "sImV4cCI6MzA2NDUxODM1NiwiaXNzIjoiaHR0cHM6Ly8xMC4yNDQuMC4yOjg0NDMvb2F1dGgvdG9rZW4iLCJ6aWQiO"
      + "iJ1YWEiLCJhdWQiOlsiY3JlZGh1Yl9jbGkiLCJjcmVkaHViIl19.bKF1R9L_1-phmfZEeokEzdqak44ybnwrCN2LSu"
      + "-bWaJeDJyz1unJ60_p8fSEAwiNsYHNfjfXsr4YiBloFhhng_4JhVmTvcW5abo820SEWl5tEMICrqzurWzV8fZ1W0wU"
      + "Lh9GIEERc3fSOuxMqKcX-U8FeUPvQRMPVTynXqP_CsVUeZn9hxpDL2_ZUrfy0sQFkEHTrENE2Ij6ldZv5qB7LUoTpw"
      + "wgcPsLf_gc2WaBxuoD6xn7SPSTxAGZQi45CKKGWWQH8VorIVo5oWHCWkBB94kHtR03gy3VeZJT-gBT-56dtJc3Udn2"
      + "LZHz45etvYvXvl6MY0UgQLizly8fE582Yg";
  public static final String INVALID_SCOPE_SYMMETRIC_KEY_JWT = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImxlZ2F"
      + "jeS10b2tlbi1rZXkiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiJlYTYxY2VlYzM2Nzk0ZGE5OWVhYTIyMGUwYTNjYTA3ZC"
      + "IsInN1YiI6ImE1NGIxODc0LTJhZWYtNGU3Ny05OTFmLWE5N2Y4ZDExMzJlNyIsInNjb3BlIjpbImNyZWRodWIuYmFk"
      + "X3Njb3BlIl0sImNsaWVudF9pZCI6ImNyZWRodWJfY2xpIiwiY2lkIjoiY3JlZGh1Yl9jbGkiLCJhenAiOiJjcmVkaH"
      + "ViX2NsaSIsImdyYW50X3R5cGUiOiJwYXNzd29yZCIsInVzZXJfaWQiOiJhNTRiMTg3NC0yYWVmLTRlNzctOTkxZi1h"
      + "OTdmOGQxMTMyZTciLCJvcmlnaW4iOiJ1YWEiLCJ1c2VyX25hbWUiOiJjcmVkaHViX2NsaSIsImVtYWlsIjoiY3JlZG"
      + "h1Yl9jbGkiLCJhdXRoX3RpbWUiOjE0ODc3MTgzNTYsInJldl9zaWciOiJiOTFkYzZkIiwiaWF0IjoxNDg3NzE4MzU2"
      + "LCJleHAiOjMwNjQ1MTgzNTYsImlzcyI6Imh0dHBzOi8vMTAuMjQ0LjAuMjo4NDQzL29hdXRoL3Rva2VuIiwiemlkIj"
      + "oidWFhIiwiYXVkIjpbImNyZWRodWJfY2xpIiwiY3JlZGh1YiJdfQ.HtUo6XaGrf5cV4sQ3ZryFTRuEDugViLt6auUy"
      + "sMdJivrcztDMgX5zfUefHXBnat8Vo8xySiKbpLRkZ1F40z8T4VBfq6iFMeVV0T8rAe7ydrt6AHNqobdk9mjIBlGFDK"
      + "ZyNO8VNtsvKwWC2Y1gfctcBMrPgEm4AzgnydKXPS0pCs9q-0SlAVNTiOrn6b6LESvSbDp6dHt7_JAkH3ln68GQr-L0"
      + "p9nXB7LFf-qgE_h5mM3Hl6v6cq-n56n4Ne1tKgsubYmhs1FcS_-mNxl1IFP-ByZVwZYFPkf0I8q_HiURqgc6Of5LyA"
      + "sik7437N3ObseR6ImWGt1hrlgvayfztrGsg";
}
