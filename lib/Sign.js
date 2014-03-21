var crypto = require('crypto')
var _ = require('underscore')
var ursa = require('ursa')

function Sign(options) {
  this._options = options || {}
  this._options.algorithm = this._options.algorithm || 'sha256'

  if(this._options.pem && this._options.password) {
    this._key = ursa.createPrivateKey(this._options.pem, this._options.password, 'utf-8')
  } else if(this._options.pem) {
    this._key = ursa.coerceKey(this._options.pem)
  } else {
    //WARN that this should only be used for transient, short lived, non scalable systems
    this._key = ursa.generatePrivateKey(this._options.length || 4096, 65537)
  }

}

Sign.prototype.sign = function(data) {

  var buff = new Buffer(JSON.stringify(data), 'utf-8')

  var token = this._key.hashAndSign(this._options.algorithm, buff, 'hex', 'hex')

  return {
    type: 'keys',
    token: token,
    payload: data
  }

}

Sign.prototype.verify = function(data) {

  if(!data.type === 'keys' || !data.token || !data.payload) {
    return false
  }
  var buff = new Buffer(JSON.stringify(data.payload), 'utf-8')

  return this._key.hashAndVerify(this._options.algorithm, buff, data.token, 'hex')

}


module.exports = Sign
