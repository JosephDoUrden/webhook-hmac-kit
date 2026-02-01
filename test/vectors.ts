/**
 * Deterministic test vectors for webhook-hmac-kit.
 *
 * All signatures are computed with HMAC-SHA256 over the canonical string:
 *   v1:{timestamp}:{nonce}:{payload}
 *
 * To regenerate, run:
 *   node -e "const c=require('crypto'); const s='whsec_test_secret_key_1234567890';
 *   const canonical='v1:1700000000:nonce_abc123:{\"event\":\"payment.completed\",\"amount\":4999}';
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
    canonical: 'v1:1700000000:nonce_abc123:{"event":"payment.completed","amount":4999}',
    signature: 'dfa71af8832a81f0b996c3411de0b29f02a9292256a24ecf363465d3285bdc6b',
  },
  {
    name: 'empty payload',
    payload: '',
    timestamp: TEST_TIMESTAMP,
    nonce: 'nonce_empty001',
    canonical: 'v1:1700000000:nonce_empty001:',
    signature: '96771f2cf8576c2154f7fbcdcea8840087539ca78ce3a5b91539cce7354b0d05',
  },
  {
    name: 'unicode payload',
    payload: '{"name":"H\u00e9llo W\u00f6rld","emoji":"\ud83d\ude80"}',
    timestamp: TEST_TIMESTAMP,
    nonce: 'nonce_unicode01',
    canonical:
      'v1:1700000000:nonce_unicode01:{"name":"H\u00e9llo W\u00f6rld","emoji":"\ud83d\ude80"}',
    signature: '0907a577eb997d1d8d355051bd50efcb73af1075d04353c437e931b3f92f4f95',
  },
  {
    name: 'whitespace preserving',
    payload: '{  "key"  :  "value"  }',
    timestamp: TEST_TIMESTAMP,
    nonce: 'nonce_ws001',
    canonical: 'v1:1700000000:nonce_ws001:{  "key"  :  "value"  }',
    signature: 'bb75675d65f0d591e92808b7aee2c90102ed4749933190b67e1cdbd3d04fbbef',
  },
  {
    name: 'colons in payload',
    payload: '{"time":"12:30:45","url":"https://example.com"}',
    timestamp: TEST_TIMESTAMP,
    nonce: 'nonce_colon001',
    canonical: 'v1:1700000000:nonce_colon001:{"time":"12:30:45","url":"https://example.com"}',
    signature: '5270d1dd6e8807d6a92a933e6640505ff0226e4807c00d3dc70d9570fce1362e',
  },
];
