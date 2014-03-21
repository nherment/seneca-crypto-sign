

var assert = require('assert')

var Sign = require('../lib/Sign.js')

describe('Sign', function() {


  it('sign', function() {

    var sign = new Sign()

    var key = Date.now()

    var signed = sign.sign({'foo': 'bar'})
    console.log(signed)
    assert.ok(sign.verify(signed))


  })



})
