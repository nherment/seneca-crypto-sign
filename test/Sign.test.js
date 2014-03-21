

var assert = require('assert')

var Rsa = require('../lib/Rsa.js')

describe('Rsa', function() {


  it('sign', function() {

    var rsa = new Rsa({length: 512}) // make the test faster

    var key = Date.now()

    var signed = rsa.sign({'foo': 'bar'})

    assert.ok(rsa.verify(signed))

  })


  it('cannot corrupt data', function() {

    var rsa = new Rsa({length: 512}) // make the test faster

    var key = Date.now()

    var signed = rsa.sign({'foo': 'bar'})

    signed.payload.foo = 'bar2'

    assert.ok(!rsa.verify(signed))

  })



})
