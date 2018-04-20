const crypto = require('crypto');
const eccrypto = require('eccrypto');
var secp256k1 = require('secp256k1')
var shajs = require('sha.js')
global.window = global
global.XMLHttpRequest = require('w3c-xmlhttprequest').XMLHttpRequest;
const XMLHttpRequestPromise = require('xhr-promise')
var fms = process.argv[2]
function randomBuf(length = 32) {
  return new Promise((resolve, reject) => {
    crypto.randomBytes(length, (err, buf) => {
      if (err) {
        reject(err)
      } else {
        resolve(buf)
      }
    })  
  })
}

async function test()
{
    let masterseed = await randomBuf(64)
    let localkey = await randomBuf(32)
    let authkey = await randomBuf(32)
    let revokekey = await randomBuf(32)
    let localpubkey = secp256k1.publicKeyCreate(localkey, false)

    let authpubkey = secp256k1.publicKeyCreate(authkey, false)

    let revokepubkey = secp256k1.publicKeyCreate(revokekey, false)

    let ciphertext1 = await eccrypto.encrypt(localpubkey, masterseed)
    let ciphertext1_dict = {
      iv: ciphertext1.iv.toString('hex'), 
      ephemPublicKey: ciphertext1.ephemPublicKey.toString('hex'),
      ciphertext: ciphertext1.ciphertext.toString('hex')
    }
    let forgetme_upload = JSON.stringify({'authpubkey' : authpubkey.toString('hex'), 'data': ciphertext1_dict, 'revokepubkey' : revokepubkey.toString('hex')})
    var url = fms + '/store'
    
    var xhrPromise = new XMLHttpRequestPromise()
    let response = await xhrPromise.send({
       'method': 'POST',
       'url': url,
       'headers': {
         'Content-Type': 'application/json;charset=UTF-8'
       },
       'data' : forgetme_upload
    })
    console.log(JSON.stringify(response))
    
    var url = fms + '/fetch'
    let timestamp = Date.now()
    let hash = shajs('sha256').update(timestamp.toString()).digest()
    let sig = secp256k1.sign(hash, authkey)
    var fms_bundle = { 'hash': hash.toString('hex'), 'timestamp' : timestamp.toString(), 'sig' : sig.signature.toString('hex'), 'recovery' : sig.recovery }
    var xhrPromise = new XMLHttpRequestPromise()
    let response2 = await xhrPromise.send({
      'method': 'POST',
      'url': url,
      'headers': {
        'Content-Type': 'application/json;charset=UTF-8'
      },
      'data': JSON.stringify(fms_bundle)
    })
    
    console.log('fetch response: ' + response2.responseText)
    var url = fms + '/revoke'
    timestamp = new Date()
    hash = shajs('sha256').update(timestamp.toString()).digest()
    sig = secp256k1.sign(hash, revokekey)
    fms_bundle = { 'hash': hash.toString('hex'), 'timestamp' : timestamp.toString(), 'sig' : sig.signature.toString('hex'), 'recovery' : sig.recovery }
    xhrPromise = new XMLHttpRequestPromise()
    let response3 = await xhrPromise.send({
      'method': 'POST',
      'url': url,
      'headers': {
        'Content-Type': 'application/json;charset=UTF-8'
      },
      'data': JSON.stringify(fms_bundle)
    })
    console.log('revoke response: ' + JSON.stringify(response3))

    var url = fms + '/fetch'
    timestamp = Date.now()
    hash = shajs('sha256').update(timestamp.toString()).digest()
    sig = secp256k1.sign(hash, authkey)
    var fms_bundle = { 'hash': hash.toString('hex'), 'timestamp' : timestamp.toString(), 'sig' : sig.signature.toString('hex'), 'recovery' : sig.recovery }
    var xhrPromise = new XMLHttpRequestPromise()
    let response4 = await xhrPromise.send({
      'method': 'POST',
      'url': url,
      'headers': {
        'Content-Type': 'application/json;charset=UTF-8'
      },
      'data': JSON.stringify(fms_bundle)
    })
    console.log('fetch-after-revoke response ' + JSON.stringify(response4))

    var url = fms + '/health'
    var fms_bundle = {}
    var xhrPromise = new XMLHttpRequestPromise()
    let response5 = await xhrPromise.send({
      'method': 'POST',
      'url': url,
      'headers': {
        'Content-Type': 'application/json;charset=UTF-8'
      },
      'data': JSON.stringify(fms_bundle)
    })
    console.log('health response ' + JSON.stringify(response4))
}

test().then(() => {}).catch((error) => {
  console.log('error: ' + JSON.stringify(error))
})

