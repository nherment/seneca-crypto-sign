var assert = require('assert')
var seneca = require('seneca')()
var fs = require('fs')
var path = require('path')

seneca.use( require('../crypto-sign.js') )

var home = process.env[(process.platform == 'win32') ? 'USERPROFILE' : 'HOME']


describe('crypto microservice', function() {

  before(function(done) {
    seneca.ready(done)
  })

  it('default sign/verify', function(done) {

    var crypto = seneca.pin({role: 'crypto-sign', cmd: '*'})

    crypto.sign({data: {foo: 'bar'}}, function(err, signedData) {
      if(err) {
        return done(err)
      }

      crypto.verify({data: signedData}, function(err, verified) {

        if(err) {
          return done(err)
        }

        assert.ok(verified)

        signedData.payload.altered = true
        crypto.verify({data: signedData}, function(err, verified) {

          if(err) {
            return done(err)
          }

          assert.ok(!verified)
          done()

        })


      })

    })

  })

  it('hmac: configure', function(done) {

    var crypto = seneca.pin({role: 'crypto-sign', cmd: '*'})

    crypto.configure({name: 'foobar', key: 'super duper secret', type: 'hmac', algorithm: 'sha1'}, function(err) {
      if(err) {
        return done(err)
      }
      var hmac = seneca.pin({role: 'crypto-sign', cmd: '*', name: 'foobar'})

      hmac.sign({data: {foo: 'bar'}}, function(err, signedData) {
        if(err) {
          return done(err)
        }


        hmac.verify({data: signedData}, function(err, verified) {

          if(err) {
            return done(err)
          }

          assert.ok(verified)


          signedData.payload.altered = true
          hmac.verify({data: signedData}, function(err, verified) {

            if(err) {
              return done(err)
            }

            assert.ok(!verified)
            done()

          })

        })

      })

    })

  })


  it('rsa: configure', function(done) {

    var crypto = seneca.pin({role: 'crypto-sign', cmd: '*'})

    crypto.configure({name: 'foobar', pem: fs.readFileSync(home + '/.ssh/id_rsa'), type: 'rsa', length: 512}, function(err) {
      if(err) {
        return done(err)
      }
      var rsa = seneca.pin({role: 'crypto-sign', cmd: '*', name: 'foobar'})

      rsa.sign({data: {foo: 'bar'}}, function(err, signedData) {
        if(err) {
          return done(err)
        }


        rsa.verify({data: signedData}, function(err, verified) {

          if(err) {
            return done(err)
          }

          assert.ok(verified)


          signedData.payload.altered = true
          rsa.verify({data: signedData}, function(err, verified) {

            if(err) {
              return done(err)
            }

            assert.ok(!verified)
            done()

          })

        })

      })

    })

  })
})
