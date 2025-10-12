# Check Cert validity
- Uses `http.Client{Timeout: ...}` to enforce a request timeout.
- Uses `tls.Config{InsecureSkipVerify: false}` to ensure TLS certs are verified.
- Displays a countdown progress bar before each request using # characters.
- Measures and prints the actual time taken for each URL test.

