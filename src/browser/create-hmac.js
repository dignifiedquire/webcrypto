'use strict'

const crypto = window.crypto.subtle

const hashTypes = {
  sha1: 'SHA-1',
  sha256: 'SHA-256',
  sha512: 'SHA-512'
}

module.exports = function createHmac (hashType, secret) {
  if (typeof secret === 'string') {
    secret = new TextEncoder('utf-8').encode(secret)
  } else if (Buffer.isBuffer(secret)) {
    secret = secret.buffer
  } else {
    throw new Error('Unsupported secret')
  }

  const keyPromise = crypto.importKey(
    'raw',
    secret,
    {
      name: 'HMAC',
      hash: {
        name: hashTypes[hashType]
      }
    },
    false,
    ['sign', 'verify']
  )

  let buffer = []

  return {
    update (buf, encoding) {
      if (buffer === null) {
        throw new Error('already used')
      }

      if (typeof buf === 'string') {
        buffer.push(new Buffer(buf, encoding || 'utf8'))
      } else {
        buffer.push(buf)
      }
    },
    digest (encoding) {
      if (buffer === null) {
        throw new Error('already used')
      }
      return keyPromise.then((key) => (
        crypto.sign(
          {name: 'HMAC'},
          key,
          Buffer.concat(buffer).buffer
        )
      ))
      .then((raw) => {
        buffer = null
        const digest = new Buffer(new Uint8Array(raw))
        return digest.toString(encoding)
      })
    }
  }
}
