const crypto = require('../')
const test = require('tape')
const fill = require('buffer-fill')

test('.createSignKeypair to create signing keypairs', t => {
  const {pk, sk} = crypto.createSignKeypair(crypto.id(32))
  t.strictEqual(pk.length, 64)
  t.strictEqual(sk.length, 128)
  t.end()
})

test('.sign and .openSigned to sign and open a message using signing keypairs', t => {
  const {pk, sk} = crypto.createSignKeypair(crypto.id(32))
  const keys2 = crypto.createSignKeypair(crypto.id(32))
  const msg = 'hallo welt'
  const signed = crypto.sign(msg, sk)
  const unsigned = crypto.openSigned(signed, pk)
  t.throws(() => crypto.openSigned(signed, keys2.pk), Error, 'invalid sig')
  t.strictEqual(unsigned, msg)
  t.end()
})

test('.createBoxKeypair encryption keypairs', t => {
  const {pk, sk} = crypto.createBoxKeypair(fill(Buffer.alloc(32), 'xyz'))
  t.strictEqual(pk.length, 64)
  t.strictEqual(sk.length, 64)
  t.end()
})

test('.hashPass to create a 32-length secret key from a password', t => {
  const pass = '123123123'
  crypto.hashPass(pass, null, function (err, pwhash) {
    if (err) throw err
    t.strictEqual(pwhash.salt.length, 32, 'salt length')
    t.strictEqual(pwhash.secret.length, 64, 'secret length')
    crypto.hashPass(pass, pwhash.salt, function (err, pwhash2) {
      if (err) throw err
      t.strictEqual(pwhash.salt, pwhash2.salt)
      t.strictEqual(pwhash.secret, pwhash2.secret)
      crypto.hashPass(pass, fill(Buffer.alloc(16), 'xyz'), function (err, pwhash3) {
        if (err) throw err
        t.notStrictEqual(pwhash2.salt, pwhash3.salt)
        t.notStrictEqual(pwhash2.secret, pwhash3.secret)
        t.end()
      })
    })
  })
})

test('.encrypt and .decrypt for symmetric encryption & decryption using a pass hash', t => {
  const pass = 'abcabcabc'
  crypto.hashPass(pass, null, function (err, pwhash) {
    if (err) throw err
    const plain = 'hi there bub'
    const encrypted = crypto.encrypt(pwhash.secret, plain)
    t.assert(encrypted.length > plain.length)
    t.throws(() => crypto.decrypt(fill(Buffer.alloc(32), 'badpass'), encrypted))
    const decrypted = crypto.decrypt(pwhash.secret, encrypted)
    t.strictEqual(decrypted, plain)
    t.end()
  })
})

test('.openBox and .createBox to send and open an encrypted (and signed) message using pubkeys', t => {
  const sender = crypto.createBoxKeypair(fill(Buffer.alloc(32), 'xyz'))
  const receiver = crypto.createBoxKeypair(fill(Buffer.alloc(32), 'abc'))
  const invalidReceiver = crypto.createBoxKeypair(fill(Buffer.alloc(32), 'def'))
  const invalidSender = crypto.createBoxKeypair(fill(Buffer.alloc(32), 'ghi'))
  const msg = 'hola mundo y buenos dias a todas personas que viven en este realidad'
  const encrypted = crypto.createBox(msg, receiver.pk, sender.sk)

  t.throws(() => crypto.openBox(encrypted, sender.pk, invalidReceiver.sk), 'Throws on invalid receiver secret key')
  t.throws(() => crypto.openBox(encrypted, invalidSender.pk, receiver.sk), 'Throws on invalid sender public key')
  const encryptedBadSig = crypto.createBox(msg, receiver.pk, invalidSender.sk)
  t.throws(() => crypto.openBox(encryptedBadSig, sender.pk, receiver.sk), 'Throws on invalid sender secret key')

  const decrypted = crypto.openBox(encrypted, sender.pk, receiver.sk)
  t.strictEqual(decrypted, msg)

  const encrypted2 = crypto.createBox(decrypted, receiver.pk, sender.sk)
  const decrypted2 = crypto.openBox(encrypted2, sender.pk, receiver.sk)
  t.notDeepEqual(encrypted, encrypted2, 'multiple encryptions produce different nonce/ciphers')
  t.strictEqual(decrypted, decrypted2, 'multiple encryptions/decryptions produce same plaintext')

  t.end()
})

test('.id to generate a simple random id', t => {
  const id = crypto.id(32)
  t.strictEqual(id.length, 64)
  const id2 = crypto.id(32)
  t.notDeepEqual(id, id2)
  const id3 = crypto.id(64)
  t.strictEqual(id3.length, 128)
  t.end()
})

test('.hash a message', t => {
  const msg = 'hola mundo'
  const hashed = crypto.hash(msg)
  t.strictEqual(hashed.length, 64)
  const hashed2 = crypto.hash(msg)
  t.strictEqual(hashed, hashed2)
  t.end()
})

test('.hashAndSign a message with a secret key, then .unhashAndVerify it', t => {
  const msg = 'hola mundo'
  const {sk, pk} = crypto.createSignKeypair(fill(Buffer.alloc(32), 'xyz'))
  const hashed = crypto.hashAndSign(msg, sk)
  t.strictEqual(hashed.length, 256)
  t.ok(crypto.unhashAndVerify(hashed, msg, pk))
  t.throws(() => crypto.unhashAndVerify(hashed, msg + '!', pk))
  t.throws(() => crypto.unhashAndVerify('a' + hashed, msg, pk))
  t.end()
})
