var crypto = require('crypto')
var _ = require('underscore')
function Hmac(options) {

  this._options = options || {}

  this._options.algorithm = this._options.algorithm || 'SHA256'

}

Hmac.prototype.sign = function(key, data) {

  var hmac = crypto.createHmac(this._options.algorithm, new Buffer(key + '', 'utf-8'))
  hmac.update(new Buffer(JSON.stringify(data), 'utf-8'))
  var hmacToken = hmac.digest('hex')

  return {
    type: 'hmac',
    token: hmacToken,
    payload: data
  }

}

Hmac.prototype.verify = function(key, data) {

  if(!data.type === 'hmac' || !data.token || !data.payload) {
    return false
  }

  var expectedData = this.sign(key, data.payload)

  return ( expectedData.token === data.token )

}


module.exports = Hmac
