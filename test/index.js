const crypto = require('../')
const test = require('tape')
const fill = require('buffer-fill')

test('create signing keypairs', t => {
  const {pk, sk} = crypto.createSignKeypair(fill(Buffer.alloc(32), 'xyz'))
  t.strictEqual(pk.length, 32)
  t.strictEqual(sk.length, 64)
  t.end()
})

test('sign and open a message using signing keypairs', t => {
  const {pk, sk} = crypto.createSignKeypair(fill(Buffer.alloc(32), 'xyz'))
  const keys2 = crypto.createSignKeypair(fill(Buffer.alloc(32), 'abc'))
  const msg = 'hallo welt'
  const signed = crypto.sign(msg, sk)
  const unsigned = crypto.openSigned(signed, pk)
  t.throws(() => crypto.openSigned(signed, keys2.pk), Error, 'invalid sig')
  t.strictEqual(unsigned, msg)
  t.end()
})

test('create encryption keypairs', t => {
  const {pk, sk} = crypto.createBoxKeypair(fill(Buffer.alloc(32), 'xyz'))
  t.strictEqual(pk.length, 32)
  t.strictEqual(sk.length, 32)
  t.end()
})

test('create a 32-length secret key from a password', t => {
  const pass = '123123123'
  crypto.hashPass(pass, null, function (err, pwhash) {
    if (err) throw err
    t.strictEqual(pwhash.salt.length, 16)
    t.strictEqual(pwhash.secret.length, 32)
    crypto.hashPass(pass, pwhash.salt, function (err, pwhash2) {
      if (err) throw err
      t.strictEqual(pwhash.salt.toString('hex'), pwhash2.salt.toString('hex'))
      t.strictEqual(pwhash.secret.toString('hex'), pwhash2.secret.toString('hex'))
      crypto.hashPass(pass, fill(Buffer.alloc(16), 'xyz'), function (err, pwhash3) {
        if (err) throw err
        t.notStrictEqual(pwhash2.salt.toString('hex'), pwhash3.salt.toString('hex'))
        t.notStrictEqual(pwhash2.secret.toString('hex'), pwhash3.secret.toString('hex'))
        t.end()
      })
    })
  })
})

test('asymmetric encryption & decryption using a pass hash', t => {
  const pass = 'abcabcabc'
  crypto.hashPass(pass, null, function (err, pwhash) {
    if (err) throw err
    const plain = 'hi there bub'
    const encrypted = crypto.encrypt(pwhash.secret, plain)
    t.assert(encrypted.length > plain.length)
    t.throws(() => crypto.decrypt('encrypted', fill(Buffer.alloc(32), 'lo')))
    const decrypted = crypto.decrypt(encrypted, pwhash.secret)
    t.strictEqual(decrypted, plain)
    t.end()
  })
})

test('send and open an encrypted (and signed) message using pubkeys', t => {
  const sender = crypto.createBoxKeypair(fill(Buffer.alloc(32), 'xyz'))
  const receiver = crypto.createBoxKeypair(fill(Buffer.alloc(32), 'abc'))
  const invalidReceiver = crypto.createBoxKeypair(fill(Buffer.alloc(32), 'def'))
  const invalidSender = crypto.createBoxKeypair(fill(Buffer.alloc(32), 'ghi'))
  const msg = 'hola mundo y buenos dias a todas personas que viven en este realidad'
  const encrypted = crypto.sendEncrypted(msg, receiver.pk, sender.sk)

  t.throws(() => crypto.openEncrypted(encrypted, sender.pk, invalidReceiver.sk), 'Throws on invalid receiver secret key')
  t.throws(() => crypto.openEncrypted(encrypted, invalidSender.pk, receiver.sk), 'Throws on invalid sender public key')
  const encryptedBadSig = crypto.sendEncrypted(msg, receiver.pk, invalidSender.sk)
  t.throws(() => crypto.openEncrypted(encryptedBadSig, sender.pk, receiver.sk), 'Throws on invalid sender secret key')

  const decrypted = crypto.openEncrypted(encrypted, sender.pk, receiver.sk)
  t.strictEqual(decrypted, msg)

  const encrypted2 = crypto.sendEncrypted(decrypted, receiver.pk, sender.sk)
  const decrypted2 = crypto.openEncrypted(encrypted2, sender.pk, receiver.sk)
  t.notDeepEqual(encrypted, encrypted2, 'multiple encryptions produce different nonce/ciphers')
  t.strictEqual(decrypted, decrypted2, 'multiple encryptions/decryptions produce same plaintext')

  t.end()
})