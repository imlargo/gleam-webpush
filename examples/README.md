# webpush examples

Runnable examples for the [`webpush`](https://github.com/imlargo/gleam-webpush)
library. They depend on the library in the parent directory, so they always
build against the current source rather than the last release.

## Generate VAPID keys

Do this once and store the keys. The public one is also what the browser needs
when it subscribes, and replacing it invalidates every existing subscription.

```sh
gleam run -m generate_keys/generate_keys
```

## Send a notification

Fill in the VAPID keys and the subscription in
`src/send_notification/send_notification.gleam`, then:

```sh
gleam run -m send_notification/send_notification
```

The subscription values come from `PushSubscription.toJSON()` in your
frontend, which gives you the `endpoint` and the `auth` and `p256dh` keys.

### What the response means

| Status | Meaning |
| --- | --- |
| 201 | Accepted by the push service |
| 401, 403 | The VAPID keys are not the ones used to subscribe, or `subscriber` was rejected |
| 404, 410 | The subscription has expired; delete it and resubscribe |
| 413 | The payload is larger than `push.max_payload_size(4096)`, 3993 bytes |
