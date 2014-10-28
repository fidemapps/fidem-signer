var expect = require('chai').expect;
var signer = require('./index');

describe('#sign', function () {
  it('should sign a request', function () {
    var request = {
      headers: {
        date: "October 26, 2014 12:00:00"
      }
    };

    var request = signer.sign(request, {
      accessKeyId: 'myAccessKeyId',
      secretAccessKey: 'mySecretAccessKey'
    });

    expect(request.headers).to.have.property('X-Fidem-Date');
    expect(request.headers).to.have.property('Authorization');

    expect(request.headers.Authorization).to.match(/FIDEM4-HMAC-SHA256 Credential=myAccessKeyId\/20141026\/fidem, SignedHeaders=date;x-fidem-date, Signature=[0-9a-f]{64}/);

    var result = signer.verify(request, {
      accessKeyId: 'myAccessKeyId',
      secretAccessKey: 'mySecretAccessKey'
    });

    expect(result).to.be.true;
  });
});
