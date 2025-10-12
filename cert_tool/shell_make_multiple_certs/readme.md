<pre>
chmod +x generate_multiple_certificates.sh menu_view_certificates_and_keys.sh
./generate_multiple_certificates.sh
./menu_view_certificates_and_keys.sh

# openssl x509 -in domain_X_0.cer -text -noout

"""
./make_multiple_certs
├── certs
│   ├── domain_X_0.cer
:
│   └── domain_X_9.cer
├── config.txt
├── generate_multiple_certificates.sh
├── keys
│   ├── domain_X_0.key
:
│   └── domain_X_9.key
├── menu_view_certificates_and_keys.sh
└── readme.md

"""
% ./menu_view_certificates_and_keys.sh
Select an option:
1. View a certificate
2. View a key
3. Exit
Enter your choice [1-3]: 1
Files in directory certs:
domain_X_0.cer
:
domain_X_9.cer
Enter the certificate file name: domain_X_.cer
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            bb:aa:cc:ee:03:55:44:f1:33:aa:aa:aa:16:aa:4e:aa:aa:44:44:33
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, ST = CA, L = SJC, O = N_labs, OU = Unit W, CN = RA_3
        Validity
            Not Before: Dec  4 17:31:47 2024 GMT
            Not After : Dec  4 17:31:47 2025 GMT
        Subject: C = US, ST = CA, L = SJC, O = N_labs, OU = Unit W, CN = RA_3
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:ee:ee:ee:6a:84:cd:d5:ee:5d:b6:aa:ee:67:fc:
                    ee:ee:ee:a5:55:09:c6:ee:94:1f:7c:7d:ee:ea:9f:
                    :
                    ee:ee:7f:ee:ee:ee:ab:55:41:9a:f5:ee:e6:96:ad:
                    70:1b
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                7D:DF:ee:F4:ee:F7:8D:B8:BB:ee:71:A5:3B:73:6B:E1:ee:ee:6B:D1
            X509v3 Authority Key Identifier: 
                7D:DF:ee:F4:ee:F7:8D:B8:BB:ee:71:A5:3B:73:6B:E1:ee:ee:ee:D1
            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        7b:9e:a4:f8:a7:ee:8b:6e:09:1e:ee:b0:fd:09:59:5f:ee:92:
        ee:ee:54:24:57:ee:0c:82:4f:d7:9b:23:a4:b2:23:ee:1b:ee:
        :
        ee:ee:5a:aa:ee:c2:e9:7b:94:b5:be:49:1a:05:b1:d7:2c:ee:
        ee:ee:ee:9e
Select an option:
1. View a certificate
2. View a key
3. Exit
Enter your choice [1-3]: 3
Exiting...
"""
</pre>