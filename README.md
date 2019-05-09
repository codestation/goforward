# GoForward

Forward received emails to Gmail by using their REST API. This is useful when you want to receive email with a custom
domain on your Gmail account.

## Options

Every command-line option has their corresponding environment variable to configure the updater.

* `--listen, -l, LISTEN`:  Address and port to listen to incoming requests, defaults to `:2525`.
* `--allowed-host, -H, ALLOWED_HOST`: Only accept emails from the specified domain, for example `example.com`.
* `--aliases, -a, ALIASES`: Map allowed usernames to email accounts. For example `admin:noreply:info=myuser@gmail.com`
   will accept emails emails from `admin@example.com`, `noreply@example.com`, `info@example.com` and inject them to the
   `myuser@gmail.com` inbox. Gmail also accepts `me` as a valid email address.
* `--credentials, -C, CREDENTIALS_FILE`: OAuth2 credentials for the Gmail account in a json file. Must have the 
  `gmail.insert` scope.
* `--token, -T, TOKEN_FILE`: Authorization token in a json file. This can be requested by the `--request` command.
* `--tls, -t, TLS`: Allow the server to accept the STARTTLS command. This will generate a self-signed certificate
   if none are provided.
* `--private-key, -k, PRIVATE_KEY_FILE`: Path where the private key is stored. The `public-key` must also be defined,
  else this will be ignored.
* `--public-key, -K, PUBLIC_KEY_FILE`: Path where the public key is stored. The `private-key` must also be defined,
  else this will be ignored.
* `--debug, -d ,DEBUG`: Enables debug logging.
