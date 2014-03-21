

var assert = require('assert')

var Hmac = require('../lib/Hmac.js')

describe('Hmac', function() {


  it('sign', function() {

    var hmac = new Hmac()

    var key = Date.now()

    var signed = hmac.sign(key, {'foo': 'bar'})

    assert.ok(!hmac.verify(key+1, signed))
    assert.ok(!hmac.verify(key-1, signed))
    assert.ok(hmac.verify(key, signed))


  })

  it('cannot corrupt data', function() {

    var hmac = new Hmac()

    var key = Date.now()

    var signed = hmac.sign(key, {'foo': 'bar'})

    signed.payload.bar = 'foo'

    assert.ok(!hmac.verify(key, signed))

  })



})
