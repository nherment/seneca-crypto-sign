
var Rsa     = require('./lib/Rsa.js')
var Hmac    = require('./lib/Hmac.js')

var plugin  = 'crypto-sign'

module.exports = function (options) {

  var seneca = this

  seneca.add({role: 'crypto-sign', cmd: 'configure'}, configure)

  // register default sign/verify microservices
  registerHmacSigner(null, options.key, null)

  function configure(args, callback) {

    if(!args.name) {
      var err = new Error('missing name argument to identify the new signer')
      seneca.log.error(err)
      return callback(err, undefined)
    }

    if(!args.type) {
      var err = new Error('missing type argument to generate the new signer')
      seneca.log.error(err)
      return callback(err, undefined)
    }

    switch(args.type) {
      case 'hmac':
        registerHmacSigner(args.name, args.key || options.key, args.algorithm)
        break
      case 'rsa':
        registerRsaSigner(args.name, args.pem, args.key || options.key, args.algorithm, args.length)
        break
    }

    callback()

  }

  function registerHmacSigner(name, key, algorithm) {

    var hmac = new Hmac({algorithm: algorithm})

    var signFilter    = {role: plugin, cmd: 'sign'}
    var verifyFilter  = {role: plugin, cmd: 'verify'}

    if(name) {
      signFilter.name = name
      verifyFilter.name = name
    }

    seneca.add(signFilter, sign)
    seneca.add(verifyFilter, verify)

    function sign(args, callback) {
      var signedObj = hmac.sign(key, args.data)
      callback(undefined, signedObj)
    }

    function verify(args, callback) {
      var verified = hmac.verify(key, args.data)
      callback(undefined, verified)
    }
  }

  function registerRsaSigner(name, pem, password, algorithm, primeLength) {

    var rsa = new Rsa({pem: pem, password: password, algorithm: algorithm, length: primeLength})

    var signFilter    = {role: plugin, cmd: 'sign'}
    var verifyFilter  = {role: plugin, cmd: 'verify'}

    if(name) {
      signFilter.name = name
      verifyFilter.name = name
    }

    seneca.add(signFilter, sign)
    seneca.add(verifyFilter, verify)

    function sign(args, callback) {
      var signedObj = rsa.sign(args.data)
      callback(undefined, signedObj)
    }

    function verify(args, callback) {
      var verified = rsa.verify(args.data)
      callback(undefined, verified)
    }
  }

  return {
    name: plugin
  }
}
