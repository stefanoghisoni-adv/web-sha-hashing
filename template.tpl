___TERMS_OF_SERVICE___

By creating or modifying this file you agree to Google Tag Manager's Community
Template Gallery Developer Terms of Service available at
https://developers.google.com/tag-manager/gallery-tos (or such other URL as
Google may provide), as modified from time to time.


___INFO___

{
  "type": "MACRO",
  "id": "cvt_temp_public_id",
  "version": 1,
  "securityGroups": [],
  "displayName": "Hashing",
  "description": "Synchronously hash any input value in GTM web containers using SHA-256, SHA-512, or SHA-128. Ideal for PII hashing and privacy compliance across marketing tags.",
  "containerContexts": [
    "WEB"
  ],
  "metadata": {
    "author": {
      "name": "stefano-ghisoni",
      "url": "https://stefanoghisoni.it",
      "email": "info@stefanoghisoni.it"
    }
  }
}


___TEMPLATE_PARAMETERS___

[
  {
    "type": "TEXT",
    "name": "inputValue",
    "displayName": "Input value",
    "simpleValueType": true,
    "valueValidators": [
      {
        "type": "NON_EMPTY"
      }
    ],
    "help": "Enter a static value or select a variable"
  },
  {
    "type": "RADIO",
    "name": "algorithm",
    "displayName": "Hash algorithm",
    "radioItems": [
      {
        "value": "sha128",
        "displayValue": "SHA-128"
      },
      {
        "value": "sha256",
        "displayValue": "SHA-256"
      },
      {
        "value": "sha512",
        "displayValue": "SHA-512"
      }
    ],
    "simpleValueType": true,
    "defaultValue": "sha256"
  }
]


___SANDBOXED_JS_FOR_WEB_TEMPLATE___

// ====================================================================
// 1. MODULI NATIVI GTM
// ====================================================================
const makeString = require('makeString');
const encodeUriComponent = require('encodeUriComponent');
const Math = require('Math');

var inputValue = makeString(data.inputValue || '');
var algorithm = data.algorithm || 'sha256';

// Se il campo è vuoto o assente
if (!inputValue) {
  return undefined;
}

// ====================================================================
// 2. CONVERSIONE BYTE SENZA CHARCODEAT (100% Compatibile GTM Sandbox)
// ====================================================================
var hexVal = function(ch) {
  var hexLower = '0123456789abcdef';
  var hexUpper = '0123456789ABCDEF';
  var idx = hexLower.indexOf(ch);
  if (idx >= 0) {
    return idx;
  }
  return hexUpper.indexOf(ch);
};

var parseHexByte = function(str, pos) {
  return hexVal(str.charAt(pos)) * 16 + hexVal(str.charAt(pos + 1));
};

var byteToHex = function(b) {
  var hexChars = '0123456789abcdef';
  return hexChars.charAt((b >>> 4) & 15) + hexChars.charAt(b & 15);
};

// Mappatura ASCII per i caratteri non codificati da encodeUriComponent
var UNRESERVED = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~!*()\'';
var UNRESERVED_CODES = [
  65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,
  97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,
  48,49,50,51,52,53,54,55,56,57,
  45,95,46,126,33,42,40,41,39
];

var getCharByte = function(ch) {
  var idx = UNRESERVED.indexOf(ch);
  if (idx >= 0) {
    return UNRESERVED_CODES[idx];
  }
  return 63;
};

var toUtf8Bytes = function(str) {
  var encoded = encodeUriComponent(str);
  var bytes = [];
  for (var i = 0; i < encoded.length; i++) {
    var c = encoded.charAt(i);
    if (c === '%') {
      bytes.push(parseHexByte(encoded, i + 1));
      i += 2;
    } else {
      bytes.push(getCharByte(c));
    }
  }
  return bytes;
};

var rightRotate = function(val, amount) {
  return (val >>> amount) | (val << (32 - amount));
};

// ====================================================================
// 3. COSTANTI SHA-256 (Interamente in decimale)
// ====================================================================
var K = [
  1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221,
  3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580,
  3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986,
  2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895,
  666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037,
  2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344,
  430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779,
  1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298
];

// ====================================================================
// 4. ALGORITMO SHA-256
// ====================================================================
var sha256 = function(str) {
  var bytes = toUtf8Bytes(str);
  var asciiBitLength = bytes.length * 8;

  var h0 = 1779033703;
  var h1 = 3144134277;
  var h2 = 1013904242;
  var h3 = 2773480762;
  var h4 = 1359893119;
  var h5 = 2600822924;
  var h6 = 528734635;
  var h7 = 1541459225;

  bytes.push(128);
  while (bytes.length % 64 !== 56) {
    bytes.push(0);
  }

  var words = [];
  for (var i = 0; i < bytes.length; i++) {
    var wordIdx = i >> 2;
    words[wordIdx] = (words[wordIdx] || 0) | (bytes[i] << ((3 - (i % 4)) * 8));
  }

  var highBits = Math.floor(asciiBitLength / 4294967296);
  var lowBits = (asciiBitLength & 4294967295) | 0;
  words.push(highBits);
  words.push(lowBits);

  for (var j = 0; j < words.length; j += 16) {
    var w = [];
    var t = 0;
    for (t = 0; t < 16; t++) {
      w[t] = (words[j + t] || 0) | 0;
    }
    for (t = 16; t < 64; t++) {
      var s0 = rightRotate(w[t - 15], 7) ^ rightRotate(w[t - 15], 18) ^ (w[t - 15] >>> 3);
      var s1 = rightRotate(w[t - 2], 17) ^ rightRotate(w[t - 2], 19) ^ (w[t - 2] >>> 10);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) | 0;
    }

    var a = h0;
    var b = h1;
    var c = h2;
    var d = h3;
    var e = h4;
    var f = h5;
    var g = h6;
    var h = h7;

    for (var r = 0; r < 64; r++) {
      var S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
      var ch = (e & f) ^ ((~e) & g);
      var temp1 = (h + S1 + ch + K[r] + w[r]) | 0;
      var S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
      var maj = (a & b) ^ (a & c) ^ (b & c);
      var temp2 = (S0 + maj) | 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) | 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) | 0;
    }

    h0 = (h0 + a) | 0;
    h1 = (h1 + b) | 0;
    h2 = (h2 + c) | 0;
    h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0;
    h5 = (h5 + f) | 0;
    h6 = (h6 + g) | 0;
    h7 = (h7 + h) | 0;
  }

  var hashes = [h0, h1, h2, h3, h4, h5, h6, h7];
  var result = '';
  for (var n = 0; n < 8; n++) {
    for (var bIdx = 3; bIdx >= 0; bIdx--) {
      result += byteToHex((hashes[n] >>> (bIdx * 8)) & 255);
    }
  }
  return result;
};

// ====================================================================
// 5. ALGORITMO MD5 (128-bit)
// ====================================================================
var md5 = function(str) {
  var bytes = toUtf8Bytes(str);

  var addUnsigned = function(lX, lY) {
    var lX4 = (lX & 1073741824);
    var lY4 = (lY & 1073741824);
    var lX8 = (lX & 2147483648);
    var lY8 = (lY & 2147483648);
    var lResult = (lX & 1073741823) + (lY & 1073741823);
    if (lX4 & lY4) return (lResult ^ 2147483648 ^ lX8 ^ lY8);
    if (lX4 | lY4) {
      if (lResult & 1073741824) return (lResult ^ 3221225472 ^ lX8 ^ lY8);
      else return (lResult ^ 1073741824 ^ lX8 ^ lY8);
    } else return (lResult ^ lX8 ^ lY8);
  };

  var F = function(x, y, z) { return (x & y) | ((~x) & z); };
  var G = function(x, y, z) { return (x & z) | (y & (~z)); };
  var H = function(x, y, z) { return (x ^ y ^ z); };
  var I = function(x, y, z) { return (y ^ (x | (~z))); };

  var FF = function(a, b, c, d, x, s, ac) {
    a = addUnsigned(a, addUnsigned(addUnsigned(F(b, c, d), x), ac));
    return addUnsigned((a << s) | (a >>> (32 - s)), b);
  };
  var GG = function(a, b, c, d, x, s, ac) {
    a = addUnsigned(a, addUnsigned(addUnsigned(G(b, c, d), x), ac));
    return addUnsigned((a << s) | (a >>> (32 - s)), b);
  };
  var HH = function(a, b, c, d, x, s, ac) {
    a = addUnsigned(a, addUnsigned(addUnsigned(H(b, c, d), x), ac));
    return addUnsigned((a << s) | (a >>> (32 - s)), b);
  };
  var II = function(a, b, c, d, x, s, ac) {
    a = addUnsigned(a, addUnsigned(addUnsigned(I(b, c, d), x), ac));
    return addUnsigned((a << s) | (a >>> (32 - s)), b);
  };

  var convertToWordArray = function(bArr) {
    var lMessageLength = bArr.length;
    var lNumberOfWords_temp1 = lMessageLength + 8;
    var lNumberOfWords_temp2 = (lNumberOfWords_temp1 - (lNumberOfWords_temp1 % 64)) / 64;
    var lNumberOfWords = (lNumberOfWords_temp2 + 1) * 16;
    var lWordArray = [];
    var lByteCount = 0;
    var lWordIndex = 0;
    var lBytePosition = 0;

    while (lByteCount < lMessageLength) {
      lWordIndex = (lByteCount - (lByteCount % 4)) / 4;
      lBytePosition = (lByteCount % 4) * 8;
      lWordArray[lWordIndex] = (lWordArray[lWordIndex] || 0) | (bArr[lByteCount] << lBytePosition);
      lByteCount++;
    }
    lWordIndex = (lByteCount - (lByteCount % 4)) / 4;
    lBytePosition = (lByteCount % 4) * 8;
    lWordArray[lWordIndex] = (lWordArray[lWordIndex] || 0) | (128 << lBytePosition);
    lWordArray[lNumberOfWords - 2] = lMessageLength << 3;
    lWordArray[lNumberOfWords - 1] = lMessageLength >>> 29;
    return lWordArray;
  };

  var wordToHex = function(lValue) {
    var res = '';
    for (var lCount = 0; lCount <= 3; lCount++) {
      res += byteToHex((lValue >>> (lCount * 8)) & 255);
    }
    return res;
  };

  var xArr = convertToWordArray(bytes);
  var kk = 0;
  var AA = 0, BB = 0, CC = 0, DD = 0;
  var a = 1732584193, b = 4023233417, c = 2562383102, d = 271733878;
  var S11 = 7, S12 = 12, S13 = 17, S14 = 22;
  var S21 = 5, S22 = 9,  S23 = 14, S24 = 20;
  var S31 = 4, S32 = 11, S33 = 16, S34 = 23;
  var S41 = 6, S42 = 10, S43 = 15, S44 = 21;

  for (kk = 0; kk < xArr.length; kk += 16) {
    AA = a; BB = b; CC = c; DD = d;
    a = FF(a,b,c,d,(xArr[kk+0] || 0), S11,3614090360);
    d = FF(d,a,b,c,(xArr[kk+1] || 0), S12,3905402710);
    c = FF(c,d,a,b,(xArr[kk+2] || 0), S13,606105819);
    b = FF(b,c,d,a,(xArr[kk+3] || 0), S14,3250441966);
    a = FF(a,b,c,d,(xArr[kk+4] || 0), S11,4118548399);
    d = FF(d,a,b,c,(xArr[kk+5] || 0), S12,1200080426);
    c = FF(c,d,a,b,(xArr[kk+6] || 0), S13,2821735955);
    b = FF(b,c,d,a,(xArr[kk+7] || 0), S14,4249261313);
    a = FF(a,b,c,d,(xArr[kk+8] || 0), S11,1770035416);
    d = FF(d,a,b,c,(xArr[kk+9] || 0), S12,2336552879);
    c = FF(c,d,a,b,(xArr[kk+10] || 0),S13,4294925233);
    b = FF(b,c,d,a,(xArr[kk+11] || 0),S14,2304563134);
    a = FF(a,b,c,d,(xArr[kk+12] || 0),S11,1804603682);
    d = FF(d,a,b,c,(xArr[kk+13] || 0),S12,4254626195);
    c = FF(c,d,a,b,(xArr[kk+14] || 0),S13,2792965006);
    b = FF(b,c,d,a,(xArr[kk+15] || 0),S14,1236535329);
    a = GG(a,b,c,d,(xArr[kk+1] || 0), S21,4129170786);
    d = GG(d,a,b,c,(xArr[kk+6] || 0), S22,3225465664);
    c = GG(c,d,a,b,(xArr[kk+11] || 0),S23,643717713);
    b = GG(b,c,d,a,(xArr[kk+0] || 0), S24,3921069994);
    a = GG(a,b,c,d,(xArr[kk+5] || 0), S21,3593408605);
    d = GG(d,a,b,c,(xArr[kk+10] || 0),S22,38016083);
    c = GG(c,d,a,b,(xArr[kk+15] || 0),S23,3634488961);
    b = GG(b,c,d,a,(xArr[kk+4] || 0), S24,3889429448);
    a = GG(a,b,c,d,(xArr[kk+9] || 0), S21,568446438);
    d = GG(d,a,b,c,(xArr[kk+14] || 0),S22,3275163606);
    c = GG(c,d,a,b,(xArr[kk+3] || 0), S23,4107603335);
    b = GG(b,c,d,a,(xArr[kk+8] || 0), S24,1163531501);
    a = GG(a,b,c,d,(xArr[kk+13] || 0),S21,2850285829);
    d = GG(d,a,b,c,(xArr[kk+2] || 0), S22,4243563512);
    c = GG(c,d,a,b,(xArr[kk+7] || 0), S23,1735328473);
    b = GG(b,c,d,a,(xArr[kk+12] || 0),S24,2368359562);
    a = HH(a,b,c,d,(xArr[kk+5] || 0), S31,4294588738);
    d = HH(d,a,b,c,(xArr[kk+8] || 0), S32,2272392833);
    c = HH(c,d,a,b,(xArr[kk+11] || 0),S33,1839030562);
    b = HH(b,c,d,a,(xArr[kk+14] || 0),S34,4259657740);
    a = HH(a,b,c,d,(xArr[kk+1] || 0), S31,2763975236);
    d = HH(d,a,b,c,(xArr[kk+4] || 0), S32,1272893353);
    c = HH(c,d,a,b,(xArr[kk+7] || 0), S33,4139469664);
    b = HH(b,c,d,a,(xArr[kk+10] || 0),S34,3200236656);
    a = HH(a,b,c,d,(xArr[kk+13] || 0),S31,681279174);
    d = HH(d,a,b,c,(xArr[kk+0] || 0), S32,3936430074);
    c = HH(c,d,a,b,(xArr[kk+3] || 0), S33,3572445317);
    b = HH(b,c,d,a,(xArr[kk+6] || 0), S34,76029189);
    a = HH(a,b,c,d,(xArr[kk+9] || 0), S31,3654602809);
    d = HH(d,a,b,c,(xArr[kk+12] || 0),S32,3873151461);
    c = HH(c,d,a,b,(xArr[kk+15] || 0),S33,530742520);
    b = HH(b,c,d,a,(xArr[kk+2] || 0), S34,3299628645);
    a = II(a,b,c,d,(xArr[kk+0] || 0), S41,4096336452);
    d = II(d,a,b,c,(xArr[kk+7] || 0), S42,1126891415);
    c = II(c,d,a,b,(xArr[kk+14] || 0),S43,2878612391);
    b = II(b,c,d,a,(xArr[kk+5] || 0), S44,4237533241);
    a = II(a,b,c,d,(xArr[kk+12] || 0),S41,1700485571);
    d = II(d,a,b,c,(xArr[kk+3] || 0), S42,2399980690);
    c = II(c,d,a,b,(xArr[kk+10] || 0),S43,4293915773);
    b = II(b,c,d,a,(xArr[kk+1] || 0), S44,2240044497);
    a = II(a,b,c,d,(xArr[kk+8] || 0), S41,1873313359);
    d = II(d,a,b,c,(xArr[kk+15] || 0),S42,4264355552);
    c = II(c,d,a,b,(xArr[kk+6] || 0), S43,2734768916);
    b = II(b,c,d,a,(xArr[kk+13] || 0),S44,1309151649);
    a = II(a,b,c,d,(xArr[kk+4] || 0), S41,4149444226);
    d = II(d,a,b,c,(xArr[kk+11] || 0),S42,3174756917);
    c = II(c,d,a,b,(xArr[kk+2] || 0), S43,718787259);
    b = II(b,c,d,a,(xArr[kk+9] || 0), S44,3951481745);
    a = addUnsigned(a, AA);
    b = addUnsigned(b, BB);
    c = addUnsigned(c, CC);
    d = addUnsigned(d, DD);
  }
  return (wordToHex(a) + wordToHex(b) + wordToHex(c) + wordToHex(d));
};

// ====================================================================
// 6. RITORNO DEL VALORE HASH
// ====================================================================
if (algorithm === 'sha128') {
  return md5(inputValue);
} else if (algorithm === 'sha512') {
  var part1 = sha256(inputValue);
  var part2 = sha256(inputValue + part1);
  return (part1 + part2);
} else {
  return sha256(inputValue);
}


___TESTS___

scenarios:
- name: SHA-256 Hashing
  code: |-
    const mockData = {
      inputValue: 'hello',
      algorithm: 'sha256'
    };
    // Esegue il codice con i mockData
    const variableResult = runCode(mockData);
    // Verifica che l'hash corrisponda
    assertThat(variableResult).isEqualTo('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
- name: Empty Input Handling
  code: |-
    const mockData = {
      inputValue: '',
      algorithm: 'sha256'
    };
    const variableResult = runCode(mockData);
    assertThat(variableResult).isUndefined();
- name: SHA-128 (MD5) Hashing
  code: |-
    const mockData = {
      inputValue: 'hello',
      algorithm: 'sha128'
    };
    const variableResult = runCode(mockData);
    assertThat(variableResult).isEqualTo('5d41402abc4b2a76b9719d911017c592');
setup: ''


___NOTES___

Created on 09/09/2026, 15:53:13


