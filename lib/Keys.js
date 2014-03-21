var crypto = require('crypto');

function Keys(length) {
  this._dh = crypto.createDiffieHellman(length);
  this._dh.generateKeys()
}


Keys.prototype.public = function(encoding) {
  return this._dh.getPublicKey(encoding)
}

Keys.prototype.private = function(encoding) {
  return this._dh.getPrivateKey(encoding)
}

module.exports = Keys
