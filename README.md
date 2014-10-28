# fidem-signer

[ ![Codeship Status for sguimont/fidem-signer](https://www.codeship.io/projects/e9a7de60-3b6e-0132-01f2-7235cdea93e5/status)](https://www.codeship.io/projects/42653)

Library for signing Fidem HTTP Request

## Usage

```js
var signer = require('fidem-signer');

// Sign a request.
request = signer.sign(request, credentials);

// Verify a request.
var valid = signer.verify(request, credentials);
```

## License

MIT
