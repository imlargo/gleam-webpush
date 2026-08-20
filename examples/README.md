# webpush examples

Runnable examples for the [`webpush`](https://github.com/imlargo/gleam-webpush)
library. They depend on the library in the parent directory, so they always
build against the current source rather than the last release.

## Generate VAPID keys

Do this once and store the keys. The public key is also what the browser needs
when it subscribes.

```sh
gleam run -m generate_keys/generate_keys
```

## Send a notification

Fill in the subscription and the VAPID keys in
`src/send_notification/send_notification.gleam`, then:

```sh
gleam run -m send_notification/send_notification
```
