// webhook-hmac-kit@2.0.0   signs  v2.{timestamp}.{nonce}.{payload}   nonce is dot-free
import { signWebhook, verifyWebhook } from 'webhook-hmac-kit';

const base = { secrets: 'whsec_demo', timestamp: Math.floor(Date.now() / 1000) };

// sender: nonce "abc", payload "a.b.c" (dots in the payload are fine)
const { signature } = await signWebhook({ ...base, nonce: 'abc', payload: 'a.b.c' });
console.log('signed    nonce=abc    payload=a.b.c');
console.log('sig      ', signature);
const ok = await verifyWebhook({ ...base, signature, nonce: 'abc', payload: 'a.b.c' });
console.log('verified  nonce=abc    payload=a.b.c  ->', ok);

// attacker: same bytes, split differently: nonce "abc.a", payload "b.c"
try {
  await verifyWebhook({ ...base, signature, nonce: 'abc.a', payload: 'b.c' });
} catch (err) {
  console.log('verified  nonce=abc.a  payload=b.c    ->', err.name, err.code);
}
