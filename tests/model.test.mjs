import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto, createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { validateConfig, hashParts, rangeRequest, matchRange, checkPassword } from '../web/model.mjs';

const config = validateConfig(JSON.parse(await readFile(new URL('../web/config.json', import.meta.url))));
const suffix = '1E4C9B93F3F0682250B6CF8331B7EE68FD8';
const other = 'A'.repeat(35);
const padding = 'B'.repeat(35);
const fixture = `${suffix}:42\r\n${other}:7\r\n${padding}:0\r\n`;

test('public test vector is SHA-1 of exact UTF-8 input', async () => {
  assert.deepEqual(await hashParts('password', 4096, webcrypto), { prefix:'5BAA6', suffix });
  for (const input of [' password ', 'Password', 'é', 'e\u0301', '🫧']) {
    const hash = createHash('sha1').update(input, 'utf8').digest('hex').toUpperCase();
    const parts = await hashParts(input, 4096, webcrypto);
    assert.equal(parts.prefix + parts.suffix, hash);
  }
});
test('empty input, UTF-8 size and missing Web Crypto fail before networking', async () => {
  await assert.rejects(hashParts('', 10, webcrypto), /Enter/);
  await assert.rejects(hashParts('éé', 3, webcrypto), /UTF-8 bytes/);
  await assert.rejects(hashParts('password', 20, {}), /Web Crypto/);
  assert.throws(() => validateConfig({ ...config, timeoutMs:0 }), /configuration/);
});
test('only a five-character prefix can become an outbound request', () => {
  const [url, options] = rangeRequest('5BAA6');
  assert.equal(url, 'https://api.pwnedpasswords.com/range/5BAA6');
  assert.equal(options.headers['Add-Padding'], 'true');
  assert.equal(options.method, 'GET');
  assert.equal(options.credentials, 'omit');
  assert.equal(options.referrerPolicy, 'no-referrer');
  assert.equal(options.redirect, 'error');
  assert.equal(options.cache, 'no-store');
  assert.equal(options.body, undefined);
  for (const value of ['password', '5BAA6'+suffix, suffix, '1234', '123456', 'ZZZZZ', '5BAA6?x=1']) assert.throws(() => rangeRequest(value), /five/);
});
test('local exact matching ignores padding and never returns hashes', () => {
  assert.deepEqual(matchRange(fixture, suffix), {found:true, count:42});
  assert.deepEqual(matchRange(fixture, padding), {found:false,count:0});
  assert.deepEqual(matchRange(fixture, 'C'.repeat(35)), {found:false,count:0});
  assert.deepEqual(matchRange(`${suffix.toLowerCase()}:42\n${other}:1`, suffix), {found:true,count:42});
});
test('malformed responses cannot become a reassuring no-match', () => {
  for (const bad of ['', '<html>challenge</html>', `${suffix}:NaN`, `${suffix}:-1`, `${suffix}:1.5`, `${suffix}:9007199254740992`, `${suffix}:3\nBAD`, `${padding}:0`, `${suffix}:1\n${suffix}:2`]) {
    assert.throws(() => matchRange(bad, suffix));
  }
});
test('integration sends no password or full hash, then returns only the local verdict', async () => {
  let calls = 0;
  const result = await checkPassword('password', config, { cryptoProvider:webcrypto, fetcher:async (url, options) => {
    calls++;
    assert.equal(url, 'https://api.pwnedpasswords.com/range/5BAA6');
    const serialized = JSON.stringify({url,options});
    assert.ok(!serialized.includes('5BAA6' + suffix));
    assert.ok(!serialized.includes(suffix));
    assert.equal(options.body, undefined);
    return new Response(fixture, {status:200});
  } });
  assert.equal(calls,1);
  assert.deepEqual(result,{found:true,count:42});
});
test('failed, cancelled, empty and oversized checks are errors rather than no-matches', async () => {
  const options = {cryptoProvider:webcrypto};
  await assert.rejects(checkPassword('password', config, {...options,fetcher:async()=>new Response('wait',{status:429})}), /pause/);
  await assert.rejects(checkPassword('password', config, {...options,fetcher:async()=>new Response('',{status:200})}), /empty/);
  await assert.rejects(checkPassword('password', config, {...options,fetcher:async()=>new Response(fixture,{headers:{'content-length':'9000000'}})}), /size limit/);
  await assert.rejects(checkPassword('password', {...config,maxResponseBytes:40000}, {...options,fetcher:async()=>new Response('A'.repeat(40001))}), /size limit/);
  const controller = new AbortController(); controller.abort();
  let called = false;
  await assert.rejects(checkPassword('password', config, {...options,signal:controller.signal,fetcher:async()=>{called=true;}}), {name:'AbortError'});
  assert.equal(called,false);
});
