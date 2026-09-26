#!/usr/bin/env node
/**
 * Собирает index.html с экраном входа: шифрует app.html паролем
 * (PBKDF2-SHA256 310k + AES-256-GCM) и встраивает в gate-template.html.
 *
 * Запуск:  PASSWORD='...' node build_gate.mjs
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { pbkdf2Sync, randomBytes, createCipheriv } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = dirname(fileURLToPath(import.meta.url));
const password = process.env.PASSWORD;
if (!password) {
  console.error('Задайте пароль: PASSWORD=... node build_gate.mjs');
  process.exit(1);
}

const appHtml = readFileSync(join(root, 'app.html'), 'utf8');
const logoB64 = 'data:image/png;base64,' + readFileSync(join(root, 'logo.png')).toString('base64');

const salt = randomBytes(16);
const iv = randomBytes(12);
const key = pbkdf2Sync(password, salt, 310000, 32, 'sha256');
const cipher = createCipheriv('aes-256-gcm', key, iv);
const ct = Buffer.concat([cipher.update(appHtml, 'utf8'), cipher.final()]);
const tag = cipher.getAuthTag();

// layout: salt(16) | iv(12) | ciphertext | tag(16)  — WebCrypto ждёт tag в конце
const payload = Buffer.concat([salt, iv, ct, tag]).toString('base64');

const template = readFileSync(join(root, 'gate-template.html'), 'utf8');
const out = template.replace('__PAYLOAD__', payload).replace('__LOGO__', logoB64);
if (out.includes('__PAYLOAD__') || out.includes('__LOGO__')) {
  console.error('Не все плейсхолдеры заменены');
  process.exit(1);
}
writeFileSync(join(root, 'index.html'), out);
console.log(`index.html собран: ${(out.length / 1024).toFixed(0)} KB (payload ${(payload.length / 1024).toFixed(0)} KB)`);
