// webhook-hmac-kit@1.0.0   signs  v1:{timestamp}:{nonce}:{payload}
import { signWebhook, verifyWebhook } from 'webhook-hmac-kit';

const base = { secret: 'whsec_demo', timestamp: Math.floor(Date.now() / 1000) };

// sender: nonce "abc", payload "a:b:c"
const { signature } = signWebhook({ ...base, nonce: 'abc', payload: 'a:b:c' });
console.log('signed    nonce=abc    payload=a:b:c');
console.log('sig      ', signature);

// attacker: same bytes, split differently: nonce "abc:a", payload "b:c"
const res = await verifyWebhook({ ...base, signature, nonce: 'abc:a', payload: 'b:c' });
console.log('verified  nonce=abc:a  payload=b:c    ->', res);
