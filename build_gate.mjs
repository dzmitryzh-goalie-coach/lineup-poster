#!/usr/bin/env node
/**
 * Собирает index.html: приложение шифруется общим мастер-ключом (master.key),
 * а ключ заворачивается паролем каждого логина из users.json.
 * Логин после входа получает ещё и свой ключ хранилища — сохранения
 * у каждого логина отдельные (и лежат в localStorage зашифрованными).
 *
 *   node add_user.mjs <логин>      # добавить логин (пароль не печатается)
 *   node build_gate.mjs            # пересобрать index.html
 *   node build_gate.mjs --users users.test.json --out index.test.html
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { randomBytes, createCipheriv } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = dirname(fileURLToPath(import.meta.url));
const ITER = 310000;

const argAfter = name => {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : '';
};
const usersPath = argAfter('--users') ? join(root, argAfter('--users')) : join(root, 'users.json');
const outPath = argAfter('--out') ? join(root, argAfter('--out')) : join(root, 'index.html');

for (const [path, hint] of [
  [join(root, 'master.key'), 'нет master.key — добавьте первый логин: node add_user.mjs <логин>'],
  [usersPath, 'нет списка логинов — добавьте: node add_user.mjs <логин>'],
  [join(root, 'app.html'), 'нет app.html — это исходник приложения'],
]) {
  if (!existsSync(path)) {
    console.error(hint);
    process.exit(1);
  }
}

const master = Buffer.from(readFileSync(join(root, 'master.key'), 'utf8').trim(), 'hex');
if (master.length !== 32) {
  console.error('master.key повреждён — ожидалось 32 байта (64 hex-символа)');
  process.exit(1);
}

const users = JSON.parse(readFileSync(usersPath, 'utf8'))
  .filter(u => u && u.login && u.salt && u.iv && u.wrapped && u.saltSave)
  .map(u => ({
    login: String(u.login),
    name: u.name ? String(u.name) : '',
    inherit: !!u.inherit,
    salt: u.salt,
    iv: u.iv,
    wrapped: u.wrapped,
    saltSave: u.saltSave,
  }));
if (!users.length) {
  console.error('в списке нет пригодных логинов — добавьте: node add_user.mjs <логин>');
  process.exit(1);
}

const appHtml = readFileSync(join(root, 'app.html'), 'utf8');
const logoB64 = 'data:image/png;base64,' + readFileSync(join(root, 'logo.png')).toString('base64');

// приложение: iv(12) | шифротекст | tag(16)
const iv = randomBytes(12);
const cipher = createCipheriv('aes-256-gcm', master, iv);
const ct = Buffer.concat([cipher.update(appHtml, 'utf8'), cipher.final()]);
const payload = Buffer.concat([iv, ct, cipher.getAuthTag()]).toString('base64');

const template = readFileSync(join(root, 'gate-template.html'), 'utf8');
const out = template
  .replace('__PAYLOAD__', payload)
  .replace('__USERS__', JSON.stringify(users))
  .replace('__ITER__', String(ITER))
  .replace('__COUNT__', String(users.length))
  .replace('__LOGO__', logoB64);

const left = ['__PAYLOAD__', '__USERS__', '__ITER__', '__COUNT__', '__LOGO__'].filter(m => out.includes(m));
if (left.length) {
  console.error('Не заменены плейсхолдеры: ' + left.join(', '));
  process.exit(1);
}

writeFileSync(outPath, out);
console.log(
  `${outPath.split('/').pop()} собран: ${(out.length / 1024).toFixed(0)} KB ` +
  `(приложение ${(payload.length / 1024).toFixed(0)} KB, логинов ${users.length}: ${users.map(u => u.login).join(', ')})`
);