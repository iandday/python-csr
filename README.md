# python-csr
Generate a key and certificate request to receive a StartSSL signed certificate.
Final created directory will contain:
    private key file
	CSR file
	StartSSL signed certificates
	PKCS12 certificate suitable for use by Sophos UTM.

Forked from: https://github.com/cjcotton/python-csr

Usage: csrgen [fqdn]

```
python csrgen test.test.com
```
