/*
 * Copyright (C) 2017 True Holding Ltd.
 *
 * Commercial License Usage
 *
 * Licensees holding valid commercial Zipper licenses may use this file in
 * accordance with the terms contained in written agreement between you and
 * True Holding Ltd.
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
var bodyParser = require('body-parser');
var secp256k1 = require('secp256k1');
var crypto = require('crypto');

app.use(cors());
app.use(bodyParser.json()); // support json encoded bodies

// pubkey to nonces
var nonces = {} 
var values = {}

// nonce values given must always be bigger than most recent one

/**
 * /set 
 * { 'signature' : hex, 'recovery' : integer, 'nonce' : hex, 'value' : hex }
 */
 
app.post('/set', function (req, res) {
    var signature = Buffer.from(req.body.signature, 'hex');
    var recovery = req.body.recovery;
    var hash = crypto.createHash('sha256').update(Buffer.from(req.body.nonce, 'hex')).update(Buffer.from(req.body.value, 'hex')).digest();

    var pubkey = secp256k1.recover(hash, signature, recovery).toString('hex');    
    var nonce = parseInt(req.body.nonce, 16);
    
    if (pubkey in nonces) {
       currentnonce = nonces[pubkey];
       if (currentnonce > nonce)
       {
          // reject tx, this nonce isn't high enough
          return;
       }
    }
    nonces[pubkey] = nonce;
    values[pubkey] = req.body.value;
});

/*
 * /value
 * { 'signature' : hex, 'recovery' : integer, 'nonce' : hex }
 * returns the stored value
*/
 
app.post('/value', function (req, res) {
    var signature = Buffer.from(req.body.signature, 'hex');
    var recovery = req.body.recovery;
    var hash = crypto.createHash('sha256').update(Buffer.from(req.body.nonce, 'hex')).digest();

    var pubkey = secp256k1.recover(hash, signature, recovery).toString('hex');    
    var nonce = parseInt(req.body.nonce, 16);
    
    if (pubkey in nonces) {
       currentnonce = nonces[pubkey];
       if (currentnonce > nonce)
       {
          // reject tx, this nonce isn't high enough
          return;
       }
    }
    nonces[pubkey] = nonce;
    req.send(values[pubkey]);
});

/*
 * /nonce
 * { 'pubkey' : 'hex' }
 * returns the current nonce
*/
 
app.post('/nonce', function (req, res) {
    var signature = Buffer.from(req.body.signature, 'hex');
    var recovery = req.body.recovery;
    var hash = crypto.createHash('sha256').update(Buffer.from(req.body.nonce, 'hex')).digest();

    req.send(nonces[pubkey]);
});


var server = app.listen(8081, "0.0.0.0", function () {
  var host = server.address().address
  var port = server.address().port
  console.log("Example app listening at http://%s:%s", host, port)
})
