/**
 * Deterministic test vectors for webhook-hmac-kit.
 *
 * `canonical` is the string that gets HMAC-SHA256'd:
 *   v2.{timestamp}.{nonce}.{payload}
 *
 * `signature` is the wire form carried in the signature header: the scheme version, `=`, then the
 * lower-case hex digest.
 *   v2={hex}
 *
 * The digest is lower-case hex and nothing else is accepted, so a sender written in another
 * language must format it with %x rather than %X.
 *
 * A payload that is not UTF-8 text has no string form, so the last vector carries its bytes and no
 * `canonical`. Its canonical value is the prefix as UTF-8 followed by those bytes, unchanged.
 *
 * To regenerate a digest, run:
 *   node -e "const c=require('crypto'); const s='whsec_test_secret_key_1234567890';
 *   const canonical='v2.1700000000.nonce_abc123.{\"event\":\"payment.completed\",\"amount\":4999}';
 *   console.log('v2='+c.createHmac('sha256',s).update(canonical).digest('hex'));"
 *
 * and for the byte vector:
 *   node -e "const c=require('crypto'); const s='whsec_test_secret_key_1234567890';
 *   const canonical=Buffer.concat([Buffer.from('v2.1700000000.nonce_bytes001.','utf8'),
 *   Buffer.from([0x7b,0xff,0x7d])]);
 *   console.log('v2='+c.createHmac('sha256',s).update(canonical).digest('hex'));"
 */

export const TEST_SECRET = 'whsec_test_secret_key_1234567890';
export const TEST_TIMESTAMP = 1700000000;

export interface TestVector {
  name: string;
  /** What goes in as the payload. Bytes when the body is not UTF-8 text. */
  payload: string | Uint8Array;
  timestamp: number;
  nonce: string;
  /** The readable canonical value. Only a text payload has one. */
  canonical?: string;
  signature: string;
}

export const vectors: TestVector[] = [
  {
    name: 'basic JSON',
    payload: '{"event":"payment.completed","amount":4999}',
    timestamp: TEST_TIMESTAMP,
    nonce: 'nonce_abc123',
    canonical: 'v2.1700000000.nonce_abc123.{"event":"payment.completed","amount":4999}',
    signature: 'v2=e797b4fdd2f6b2f3055a9ecc45985389a3458f113e4da5c7242e2aec2d733887',
  },
  {
    name: 'empty payload',
    payload: '',
    timestamp: TEST_TIMESTAMP,
    nonce: 'nonce_empty001',
    canonical: 'v2.1700000000.nonce_empty001.',
    signature: 'v2=048213db0c13dc805ae0e9242ce377d23756eb5c6103f08c18e0b9301ff277fa',
  },
  {
    name: 'unicode payload',
    payload: '{"name":"Héllo Wörld","emoji":"🚀"}',
    timestamp: TEST_TIMESTAMP,
    nonce: 'nonce_unicode01',
    canonical: 'v2.1700000000.nonce_unicode01.{"name":"Héllo Wörld","emoji":"🚀"}',
    signature: 'v2=51bc5b40b150cfb802e6a1e806b69a1e6bbe1447d020aa2a0e9053d6bbc985d2',
  },
  {
    name: 'whitespace preserving',
    payload: '{  "key"  :  "value"  }',
    timestamp: TEST_TIMESTAMP,
    nonce: 'nonce_ws001',
    canonical: 'v2.1700000000.nonce_ws001.{  "key"  :  "value"  }',
    signature: 'v2=4e4333f9ba5692cabb2478849835027c1d2fef8f333c10410955d81091c43449',
  },
  {
    name: 'colons in payload',
    payload: '{"time":"12:30:45","url":"https://example.com"}',
    timestamp: TEST_TIMESTAMP,
    nonce: 'nonce_colon001',
    canonical: 'v2.1700000000.nonce_colon001.{"time":"12:30:45","url":"https://example.com"}',
    signature: 'v2=683d5312932959699ba9c7bc12ea8ac9bddb6ab2ed9c59364435aa2cef76c991',
  },
  {
    name: 'dots and digits in payload',
    payload: '1700000001.nonce_x.{"v":"2.0.1"}',
    timestamp: TEST_TIMESTAMP,
    nonce: 'nonce_dots001',
    canonical: 'v2.1700000000.nonce_dots001.1700000001.nonce_x.{"v":"2.0.1"}',
    signature: 'v2=c3d652678911bcd059a96e0bd3aa2bee700379649037718050486ad4896acd0b',
  },
  {
    // 0xff is not valid UTF-8. Decoding this body to a string before signing it, as the adapters
    // once did, turns it into the same three replacement bytes as 0xfe would, and the two bodies
    // share a signature. The digest below is over the exact bytes.
    name: 'byte payload that is not valid UTF-8',
    payload: Uint8Array.from([0x7b, 0xff, 0x7d]),
    timestamp: TEST_TIMESTAMP,
    nonce: 'nonce_bytes001',
    signature: 'v2=6bcc8aabb3021f06f7cb713985154d03ca3916082148444bd0cc75e3837cd430',
  },
];
