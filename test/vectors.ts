/**
 * Deterministic test vectors for webhook-hmac-kit.
 *
 * All signatures are HMAC-SHA256 over the v2 canonical string:
 *   v2.{timestamp}.{nonce}.{payload}
 *
 * To regenerate, run:
 *   node -e "const c=require('crypto'); const s='whsec_test_secret_key_1234567890';
 *   const canonical='v2.1700000000.nonce_abc123.{\"event\":\"payment.completed\",\"amount\":4999}';
 *   console.log(c.createHmac('sha256',s).update(canonical).digest('hex'));"
 */

export const TEST_SECRET = 'whsec_test_secret_key_1234567890';
export const TEST_TIMESTAMP = 1700000000;

export interface TestVector {
  name: string;
  payload: string;
  timestamp: number;
  nonce: string;
  canonical: string;
  signature: string;
}

export const vectors: TestVector[] = [
  {
    name: 'basic JSON',
    payload: '{"event":"payment.completed","amount":4999}',
    timestamp: TEST_TIMESTAMP,
    nonce: 'nonce_abc123',
    canonical: 'v2.1700000000.nonce_abc123.{"event":"payment.completed","amount":4999}',
    signature: 'e797b4fdd2f6b2f3055a9ecc45985389a3458f113e4da5c7242e2aec2d733887',
  },
  {
    name: 'empty payload',
    payload: '',
    timestamp: TEST_TIMESTAMP,
    nonce: 'nonce_empty001',
    canonical: 'v2.1700000000.nonce_empty001.',
    signature: '048213db0c13dc805ae0e9242ce377d23756eb5c6103f08c18e0b9301ff277fa',
  },
  {
    name: 'unicode payload',
    payload: '{"name":"Héllo Wörld","emoji":"🚀"}',
    timestamp: TEST_TIMESTAMP,
    nonce: 'nonce_unicode01',
    canonical: 'v2.1700000000.nonce_unicode01.{"name":"Héllo Wörld","emoji":"🚀"}',
    signature: '51bc5b40b150cfb802e6a1e806b69a1e6bbe1447d020aa2a0e9053d6bbc985d2',
  },
  {
    name: 'whitespace preserving',
    payload: '{  "key"  :  "value"  }',
    timestamp: TEST_TIMESTAMP,
    nonce: 'nonce_ws001',
    canonical: 'v2.1700000000.nonce_ws001.{  "key"  :  "value"  }',
    signature: '4e4333f9ba5692cabb2478849835027c1d2fef8f333c10410955d81091c43449',
  },
  {
    name: 'colons in payload',
    payload: '{"time":"12:30:45","url":"https://example.com"}',
    timestamp: TEST_TIMESTAMP,
    nonce: 'nonce_colon001',
    canonical: 'v2.1700000000.nonce_colon001.{"time":"12:30:45","url":"https://example.com"}',
    signature: '683d5312932959699ba9c7bc12ea8ac9bddb6ab2ed9c59364435aa2cef76c991',
  },
  {
    name: 'dots and digits in payload',
    payload: '1700000001.nonce_x.{"v":"2.0.1"}',
    timestamp: TEST_TIMESTAMP,
    nonce: 'nonce_dots001',
    canonical: 'v2.1700000000.nonce_dots001.1700000001.nonce_x.{"v":"2.0.1"}',
    signature: 'c3d652678911bcd059a96e0bd3aa2bee700379649037718050486ad4896acd0b',
  },
];
