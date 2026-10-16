import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractIocs, defang, refang, iocType, isPrivateIp, isDefanged } from '../src/lib/ioc.js';

test('extracts hashes without double-counting substrings', () => {
  const sha256 = 'a'.repeat(64);
  const md5 = 'b'.repeat(32);
  const r = extractIocs(`file ${sha256} and ${md5}`);
  assert.deepEqual(r.sha256, [sha256]);
  assert.deepEqual(r.md5, [md5]);
  assert.deepEqual(r.sha1, []);
});

test('recognises defanged indicators', () => {
  const r = extractIocs('beacon to hxxps://evil[.]example[.]com/a.php and 203.0.113[.]9');
  assert.ok(r.url.includes('https://evil.example.com/a.php'));
  assert.ok(r.ipv4.includes('203.0.113.9'));
  assert.ok(r.domain.includes('evil.example.com'));
});

test('does not treat file names as domains', () => {
  const r = extractIocs('ran powershell.exe then loaded payload.dll from C:\\temp\\x.ps1');
  assert.deepEqual(r.domain, []);
});

test('defang and refang round-trip', () => {
  assert.equal(defang('https://bad.example.com/x.y'), 'hxxps://bad[.]example[.]com/x.y');
  assert.equal(defang('198.51.100.7'), '198[.]51[.]100[.]7');
  assert.equal(defang('a@example.com'), 'a[@]example[.]com');
  assert.equal(refang(defang('https://bad.example.com/x')), 'https://bad.example.com/x');
  assert.ok(isDefanged('evil[.]com'));
});

test('classifies indicator types and private IPs', () => {
  assert.equal(iocType('c'.repeat(40)), 'hash');
  assert.equal(iocType('8.8.8.8'), 'ip');
  assert.equal(iocType('hxxp://x[.]io'), 'url');
  assert.equal(iocType('example.org'), 'domain');
  assert.ok(isPrivateIp('10.1.2.3'));
  assert.ok(isPrivateIp('172.20.0.1'));
  assert.ok(isPrivateIp('100.64.0.1'));
  assert.ok(!isPrivateIp('8.8.8.8'));
});
