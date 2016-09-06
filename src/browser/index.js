'use strict'

const crypto = require('crypto-browserify')

crypto.createHmac = require('./create-hmac')

module.exports = crypto
