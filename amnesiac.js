/*
 * Copyright (C) 2017 Zipper Global Ltd.	
 *
 * Commercial License Usage
 *
 * Licensees holding valid commercial Zipper licenses may use this file in
 * accordance with the terms contained in written agreement between you and
 * Zipper Global Ltd.
 *
 * GNU Affero General Public License Usage
 *
 * Alternatively, the JavaScript code in this page is free software: you can
 * redistribute it and/or modify it under the terms of the GNU Affero General Public
 * License (GNU AGPL) as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.  The code
 * is distributed WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU AGPL for
 * more details.
 *
 * As additional permission under GNU AGPL version 3 section 7, you may
 * distribute non-source (e.g., minimized or compacted) forms of that code
 * without the copy of the GNU GPL normally required by section 4, provided
 * you include this license notice and a URL through which recipients can
 * access the Corresponding Source.
 *
 * As a special exception to the AGPL, any HTML file which merely makes
 * function calls to this code, and for that purpose includes it by reference
 * shall be deemed a separate work for copyright law purposes.  In addition,
 * the copyright holders of this code give you permission to combine this
 * code with free software libraries that are released under the GNU LGPL.
 * You may copy and distribute such a system following the terms of the GNU
 * AGPL for this code and the LGPL for the libraries.  If you modify this
 * code, you may extend this exception to your version of the code, but you
 * are not obligated to do so.  If you do not wish to do so, delete this
 * exception statement from your version.
 *
 * This license applies to this entire compilation.
 */

var express = require('express');
var cors = require('cors');
var app = express();
const CID = require('cids')
var bodyParser = require('body-parser');
const crypto = require('crypto');
var secp256k1 = require('secp256k1');
var shajs = require('sha.js');
var AWS = require('aws-sdk')
var Unixfs = require('ipfs-unixfs')
var dagPB = require('ipld-dag-pb')

var myCredentials = new AWS.SharedIniFileCredentials({profile: 'default'});
var awsconfig = new AWS.Config({
  credentials: myCredentials, region: 'eu-west-1'
});

var s3 = new AWS.S3({params: 'fms'})
app.use(cors());
app.use(bodyParser.json({limit: '50mb'})); // support json encoded bodies

app.post('/store', function (req, res) {
    if (req.body.data.length > 4096) {
      res.send(JSON.stringify({'status': 'error'}))
      return
    }
    // XXX validate this is valid public keys
    var authpubkey = req.body.authpubkey
    var data = req.body.data
    var revokepubkey = req.body.revokepubkey

    if (authpubkey === revokepubkey) {
      res.send(JSON.stringify({'status': 'error'}))
      return
    }

    var s3key_authpubkey = crypto.createHash('sha256').update(Buffer.from(req.body.authpubkey, 'hex')).digest().toString('hex')
    var s3key_revokepubkey = crypto.createHash('sha256').update(Buffer.from(req.body.revokepubkey, 'hex')).digest().toString('hex')
    console.log(s3key_authpubkey)
    let params_1 = {Bucket: 'zg-fms', Key: s3key_authpubkey, Body: JSON.stringify(data)}
    s3.upload(params_1).promise().then((data) => {
       let params_2 = {Bucket: 'zg-fms', Key: s3key_revokepubkey, Body: Buffer.from(s3key_authpubkey, 'hex')}
       s3.upload(params_2).promise().then((data) => {
          res.send(JSON.stringify({'status': 'ok'}))
       }).catch((err) => {
          res.send(JSON.stringify({'error': err}))
       })
    }).catch((err) => {
      res.send(JSON.stringify({'error': err}))
    })
});

/*
 * /value
 * { 'signature' : hex, 'recovery' : integer, 'nonce' : hex }
 * returns the stored value
*/
 
app.post('/fetch', function (req, res) {
    var signature = Buffer.from(req.body.sig, 'hex');
    var recovery = req.body.recovery;

    var hash = req.body.hash ? Buffer.from(req.body.hash, 'hex') : crypto.createHash('sha256').update(req.body.timestamp).digest();
    // XXX check that timestamp is within acceptable timing of now
    var pubkey = secp256k1.publicKeyConvert(secp256k1.recover(hash, signature, recovery), false);
    
    var s3key_authpubkey = crypto.createHash('sha256').update(pubkey).digest().toString('hex')
    console.log(s3key_authpubkey)
    
    let params_1 = {Bucket: 'zg-fms', Key: s3key_authpubkey}
    s3.getObject(params_1).promise().then((data) => {
      res.send(JSON.stringify({'data' : JSON.parse(data.Body)}))
    }).catch((err) => {
      res.send(JSON.stringify({'error': err}))
    })
});

app.post('/revoke', function (req, res) {
    var signature = Buffer.from(req.body.sig, 'hex');
    var recovery = req.body.recovery;
    var hash = crypto.createHash('sha256').update(req.body.timestamp).digest();

    var pubkey = secp256k1.publicKeyConvert(secp256k1.recover(hash, signature, recovery), false);
    var s3key_revokepubkey = crypto.createHash('sha256').update(pubkey).digest().toString('hex')

    let params_1 = {Bucket: 'zg-fms', Key: s3key_revokepubkey}
    s3.getObject(params_1).promise().then((data) => {
      let params_2 = {Bucket: 'zg-fms', Key: data.Body.toString('hex')}
      console.log(data.Body.toString('hex'))
      s3.deleteObject(params_2).promise().then((data) => {
        s3.deleteObject(params_1).promise().then((data) => {
          res.send(JSON.stringify({'status' : 'ok'}))
        }).catch((err) => {
          res.send(JSON.stringify({'error': err}))
        })
      }).catch((err) => {
        res.send(JSON.stringify({'error': err}))
      })
    }).catch((err) => {
      res.send(JSON.stringify({'error': err}))
    })
});

app.post('/perma_store', function (req, res) {
    var signature = Buffer.from(req.body.sig, 'hex')
    var recovery = req.body.recovery
    var hash = crypto.createHash('sha256').update(Buffer.from(req.body.data, 'hex')).digest()
    var pubkey = secp256k1.publicKeyConvert(secp256k1.recover(hash, signature, recovery), false);
    var s3key_pubkeyhash = crypto.createHash('sha256').update(pubkey).digest().toString('hex')
    var data = { sig: req.body.sig, recovery: req.body.recovery, data: req.body.data }
    let params_1 = {Bucket: 'z-permastore', Key: s3key_pubkeyhash, Body: JSON.stringify(data)}
    
    s3.upload(params_1).promise().then((data) => {
      res.send(JSON.stringify({'status': 'ok', 'pubkey': pubkey.toString('hex')}))
    }).catch((err) => {
      res.send(JSON.stringify({'error': err}))
    })
});

app.post('/perma_store_v2', function (req, res) {
   /* 
   'timestamp': TIMESTAMP
   'cid': '',
   'signature': {
      recovery: int
      signature: hexstring
   }
   */
   function makebuf(cid, ts) { 
     var cidobj = new CID(cid)
     var buf = Buffer.alloc(4 + cidobj.buffer.length, 0x00)
     cidobj.buffer.copy(buf, 4, 0, cidobj.buffer.length)
     buf.writeUInt32LE(ts, 0)
     return buf   
   }
   
   var buf = makebuf(req.body.cid, req.body.timestamp)
   var msg = shajs('sha256').update(buf).digest()

   var sigObj = {signature: Buffer.from(req.body.signature.signature, 'hex'), recovery: req.body.signature.recovery}
   var t = secp256k1.publicKeyConvert(secp256k1.recover(msg, sigObj.signature, sigObj.recovery), true).toString('hex')
   var newfile = Buffer.from(JSON.stringify({
     timestamp: req.body.timestamp,
     cid: req.body.cid,
     signature: {
       recovery: req.body.signature.recovery,
       signature: req.body.signature.signature
     }
   }))
   
   // self-test
   /*
   { 
     var nf = JSON.parse(newfile.toString('utf8'))
     var buf = makebuf(nf.cid, nf.timestamp)
     var msg = shajs('sha256').update(buf).digest()

     var sigObj = {signature: Buffer.from(nf.signature.signature, 'hex'), recovery: nf.signature.recovery}
     var nt = secp256k1.publicKeyConvert(secp256k1.recover(msg, sigObj.signature, sigObj.recovery), true).toString('hex')
     if (nt !== t) {
        res.send(JSON.stringify({'error': 'self test failed'}))
        return
     }
   } */
   
   var ufs = new Unixfs('file', newfile)
   dagPB.DAGNode.create(ufs.marshal(), (err, dagNode) => { 
     if (err) {
        res.send(JSON.stringify({'error': err}))
     } else {
        dagPB.util.cid(dagNode, {}, (err, cid) => { 
          if (err) {
             res.send(JSON.stringify({'error': err}))
             return
          }
          var multihash = cid.toBaseEncodedString('base58btc')
          var path = t + '/' + req.body.timestamp + '.' + req.body.cid + '.' + multihash
          let params_1 = {Bucket: 'z-permastore2', Key: 'public/ipfs/' + multihash, Body: newfile, ACL: 'public-read'}
          s3.upload(params_1).promise().then((data) => {
            let params_2 = {Bucket: 'z-permastore2', Key: 'public/permastore/' + path, Body: '', ACL: 'public-read'}
            s3.upload(params_2).promise().then((data) => {
              res.send(JSON.stringify({'status': 'ok', 'path': path}))
            }).catch((err) => {
              res.send(JSON.stringify({'error': err}))
            })
          }).catch((err) => {
            res.send(JSON.stringify({'error': err}))
          })
        })
     }
   })
})

app.post('/perma_list_v2', function (req, res) { 
   // FIXME: add ability for truncated lists (>1000 objects)
   let params_1 = {Bucket: 'z-permastore2', Prefix: 'public/permastore/' + req.body.pubkey + '/'}
   s3.listObjectsV2(params_1).promise().then((data) => {
     var allKeys = []
     data.Contents.forEach(function (content) {
        allKeys.push(content.Key.replace('public/permastore/' + req.body.pubkey + '/', ''));
     })
     allSortedKeys = allKeys.sort(function(a,b) {
        var as = a.split('.')
        var bs = b.split('.')
        if (Number(as[0]) < Number(bs[0])) {
          return -1
        } else if (Number(as[0]) == Number(bs[0])) {
          if (as[1] < bs[1]) {
            return -1
          } else if (as[1] == bs[1]) {
            if (as[2] < bs[2]) {
              return -1
            } else if (as[2] == bs[2]) {
              return 0
            } else {
              return 1
            }
          } else {
            return 1
          }
        } else {
          return 1
        }
     })
     res.send(JSON.stringify({'status': 'ok', 'response': allSortedKeys}))
   }).catch((err) => {
     res.send(JSON.stringify({'error': err}))
   })
})

app.post('/ipfs_store_v2', function (req, res) {
   var buf = Buffer.from(req.body.data, 'hex')
   var ufs = new Unixfs('file', buf)
   dagPB.DAGNode.create(ufs.marshal(), (err, dagNode) => { 
     if (err) {
        res.send(JSON.stringify({'error': err}))
     } else {
        dagPB.util.cid(dagNode, {}, (err, cid) => { 
          if (err) {
             res.send(JSON.stringify({'error': err}))
             return
          }
          var multihash = cid.toBaseEncodedString('base58btc')
          let params_1 = {Bucket: 'z-permastore2', Key: 'public/ipfs/' + multihash, Body: buf, ACL: 'public-read'}
            s3.upload(params_1).promise().then((data) => {
              res.send(JSON.stringify({'status': 'ok', 'multihash': multihash}))
            }).catch((err) => {
              res.send(JSON.stringify({'error': err}))
            })
        })
      }
   })
})

app.post('/ipfs_store', function (req, res) {
    var hash = crypto.createHash('sha256').update(Buffer.from(req.body.data, 'hex')).digest().toString('hex')
    let params_1 = {Bucket: 'z-permastore', Key: hash, Body: JSON.stringify({data: req.body.data})}
    
    s3.upload(params_1).promise().then((data) => {
      res.send(JSON.stringify({'status': 'ok', 'hash': hash}))
    }).catch((err) => {
      res.send(JSON.stringify({'error': err}))
    })
});

app.post('/ipfs_fetch', function (req, res) {
    let params_1 = {Bucket: 'z-permastore', Key: req.body.hash}
    s3.getObject(params_1).promise().then((data) => {
      res.send(JSON.stringify({'data' : JSON.parse(data.Body).data}))
    }).catch((err) => {
      res.send(JSON.stringify({'error': err}))
    })
});


app.post('/perma_fetch', function (req, res) {
    var pubkey = Buffer.from(req.body.pubkey, 'hex')
    var s3key_pubkeyhash = crypto.createHash('sha256').update(pubkey).digest().toString('hex')
    var data = { sig: req.body.sig, recovery: req.body.recovery, data: req.body.data }
    let params_1 = {Bucket: 'z-permastore', Key: s3key_pubkeyhash}
    s3.getObject(params_1).promise().then((data) => {
      res.send(JSON.stringify({'data' : JSON.parse(data.Body)}))
    }).catch((err) => {
      res.send(JSON.stringify({'error': err}))
    })
});

app.post('/mailbox_store', function (req, res) { 
   var mbox_hash = crypto.createHash('sha256').update(Buffer.from(req.body.recipient, 'hex')).digest().toString('hex')
   var attached_data = Buffer.from(req.body.data, 'hex')
   var ad_hash = crypto.createHash('sha256').update(attached_data).digest().toString('hex')
   var data = { data: req.body.data }
   let params_1 = {Bucket: 'z-permastore', Key: 'mbox/' + mbox_hash + '/' + ad_hash, Body: Buffer.from(req.body.data)}
   s3.upload(params_1).promise().then((data) => {
     res.send(JSON.stringify({'status': 'ok', 'key': 'mbox/' + mbox_hash + '/' + ad_hash}))
   }).catch((err) => {
     res.send(JSON.stringify({'error': err}))
   })
})

app.post('/mailbox_list', function (req, res) { 
   // FIXME: add ability for truncated lists (>1000 objects)
   var mbox_hash = crypto.createHash('sha256').update(Buffer.from(req.body.recipient, 'hex')).digest().toString('hex')
   let params_1 = {Bucket: 'z-permastore', Prefix: 'mbox/' + mbox_hash + '/'}
   s3.listObjectsV2(params_1).promise().then((data) => {
     var allKeys = []
     data.Contents.forEach(function (content) {
        allKeys.push(content.Key.replace('mbox/' + mbox_hash + '/', ''));
     });
     res.send(JSON.stringify({'status': 'ok', 'response': allKeys}))
   }).catch((err) => {
     res.send(JSON.stringify({'error': err}))
   })
})

app.post('/mailbox_fetch', function (req, res) {
   var mbox_hash = crypto.createHash('sha256').update(Buffer.from(req.body.recipient, 'hex')).digest().toString('hex')
   let params_1 = {Bucket: 'z-permastore', Key: 'mbox/' + mbox_hash + '/' + req.body.hash}
   s3.getObject(params_1).promise().then((data) => {
     res.send({data: data})
   }).catch((err) => {
     res.send(JSON.stringify({'error': err}))
   })
});



app.get('/health', function (req, res) {
  res.send(JSON.stringify({'notdead' : true}))
})

var server = app.listen(8081, "0.0.0.0", function () {
  var host = server.address().address
  var port = server.address().port
  console.log("Amnesiac app listening at http://%s:%s", host, port)
})

