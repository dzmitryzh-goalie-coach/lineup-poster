#!/usr/bin/env node
/**
 * Пользователи сайта: логин + пароль, у каждого своя база сохранений.
 *
 *   node add_user.mjs <логин>                  # добавить (пароль спросит без эха)
 *   node add_user.mjs <логин> --name "Имя"     # с именем для подписи в приложении
 *   node add_user.mjs <логин> --inherit        # перенять сохранения этого браузера (для своего логина)
 *   node add_user.mjs <логин> --remove         # удалить логин
 *   node add_user.mjs --list                   # список логинов
 *   node add_user.mjs --generate 10 --prefix trener
 *        # 10 логинов со случайными паролями; пароли пишутся в logins.txt,
 *        # в чат/лог не печатаются (--to <файл> меняет имя файла)
 *
 * Для скриптов: LP_PASSWORD='...' node add_user.mjs <логин>
 *
 * Пароль в файл НЕ пишется: сохраняется только мастер-ключ сайта,
 * завёрнутый ключом от пароля (PBKDF2-SHA256 310k + AES-256-GCM).
 * Без пароля users.json бесполезен, но слабый пароль подбирается оффлайн —
 * берите длинный.
 */
import { readFileSync, writeFileSync, appendFileSync, existsSync, chmodSync } from 'node:fs';
import { pbkdf2Sync, randomBytes, createCipheriv } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = dirname(fileURLToPath(import.meta.url));
const USERS_ARG = process.argv.indexOf('--users');
const USERS_PATH = USERS_ARG >= 0 && process.argv[USERS_ARG + 1]
  ? join(root, process.argv[USERS_ARG + 1]) : join(root, 'users.json');
const MASTER_PATH = join(root, 'master.key');
const ITER = 310000;

const args = process.argv.slice(2);
const flags = args.filter(a => a.startsWith('--'));
const positional = args.filter(a => !a.startsWith('--'));
const flagValue = name => {
  const i = flags.indexOf(name);
  return i >= 0 && args[args.indexOf(name) + 1] && !args[args.indexOf(name) + 1].startsWith('--')
    ? args[args.indexOf(name) + 1] : '';
};

const hex = buf => Buffer.from(buf).toString('hex');

// без похожих друг на друга знаков (0/O, 1/l/I) — пароль диктуют голосом
const PW_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';

function randomPassword(len) {
  let out = '';
  while (out.length < len) {
    for (const b of randomBytes(len)) {
      if (b < 224) out += PW_ALPHABET[b % PW_ALPHABET.length];   // 224 = 4 * 56, без смещения
      if (out.length === len) break;
    }
  }
  return out;
}
const b64 = buf => Buffer.from(buf).toString('base64');

function loadUsers() {
  if (!existsSync(USERS_PATH)) return [];
  const list = JSON.parse(readFileSync(USERS_PATH, 'utf8'));
  if (!Array.isArray(list)) throw new Error('users.json должен быть массивом');
  return list;
}

function saveUsers(list) {
  writeFileSync(USERS_PATH, JSON.stringify(list, null, 2) + '\n');
  try { chmodSync(USERS_PATH, 0o600); } catch (_) {}
}

/** Мастер-ключ сайта: одним и тем же ключом зашифровано приложение,
 *  к нему же привязан (через пароль) доступ каждого логина. */
function masterKey() {
  if (existsSync(MASTER_PATH)) {
    const key = Buffer.from(readFileSync(MASTER_PATH, 'utf8').trim(), 'hex');
    if (key.length !== 32) throw new Error('master.key повреждён — ожидалось 32 байта');
    return key;
  }
  const key = randomBytes(32);
  writeFileSync(MASTER_PATH, key.toString('hex') + '\n');
  try { chmodSync(MASTER_PATH, 0o600); } catch (_) {}
  console.log('создан master.key (в git не попадает — не теряйте его: без него сохранения логинов не расшифровать)');
  return key;
}

function userRecord(login, password, opts) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const wrapKey = pbkdf2Sync(password, salt, ITER, 32, 'sha256');
  const cipher = createCipheriv('aes-256-gcm', wrapKey, iv);
  const wrapped = Buffer.concat([cipher.update(masterKey()), cipher.final(), cipher.getAuthTag()]);
  return {
    login,
    name: opts.name || '',
    inherit: !!opts.inherit,
    salt: hex(salt),
    iv: hex(iv),
    wrapped: b64(wrapped),
    saltSave: hex(randomBytes(16)),
  };
}

function askHidden(prompt) {
  return new Promise((resolve, reject) => {
    if (!process.stdin.isTTY) {
      reject(new Error('нет терминала: задайте пароль через LP_PASSWORD=... node add_user.mjs <логин>'));
      return;
    }
    const stdin = process.stdin;
    const stdout = process.stdout;
    stdout.write(prompt);
    let buf = '';
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    const onData = ch => {
      if (ch === '\r' || ch === '\n') {
        stdin.setRawMode(false);
        stdin.pause();
        stdin.removeListener('data', onData);
        stdout.write('\n');
        resolve(buf);
      } else if (ch === '\u0003') {
        stdin.setRawMode(false);
        stdout.write('\n');
        process.exit(1);
      } else if (ch === '\u007f' || ch === '\b') {
        buf = buf.slice(0, -1);
      } else if (ch >= ' ') {
        buf += ch;
      }
    };
    stdin.on('data', onData);
  });
}

async function main() {
  const users = loadUsers();

  if (flags.includes('--list')) {
    if (!users.length) { console.log('логинов нет'); return; }
    users.forEach(u => console.log('  ' + u.login + (u.name ? ' — ' + u.name : '') + (u.inherit ? ' (перенимает старые сохранения)' : '')));
    return;
  }

  if (flags.includes('--generate')) {
    const count = parseInt(flagValue('--generate'), 10) || 0;
    if (count < 1 || count > 100) {
      console.error('Укажите количество: node add_user.mjs --generate 10 [--prefix trener] [--to logins.txt]');
      process.exit(1);
    }
    const prefix = flagValue('--prefix') || 'trener';
    const to = flagValue('--to') || 'logins.txt';
    const fresh = [];
    for (let i = 1; i <= count; i++) {
      let login = prefix + i;
      while (users.some(u => u.login === login) || fresh.some(f => f.login === login)) login = prefix + i + 'x';
      const password = randomPassword(14);
      users.push(userRecord(login, password, { name: '', inherit: false }));
      fresh.push({ login, password });
    }
    saveUsers(users);
    const stamp = new Date().toISOString().slice(0, 10);
    appendFileSync(join(root, to), [
      `# Пароли логинов сайта lineup-poster — ${stamp}`,
      '# Отдайте каждому его логин и пароль и удалите этот файл.',
      '# Восстановить пароль нельзя: в users.json лежит только мастер-ключ, завёрнутый паролем.',
      ...fresh.map(f => `${f.login}\t${f.password}`),
      '',
    ].join('\n'));
    try { chmodSync(join(root, to), 0o600); } catch (_) {}
    console.log(`добавлено логинов: ${fresh.length} — ${fresh.map(f => f.login).join(', ')}`);
    console.log(`пароли записаны в ${to}; логинов в сборке теперь ${users.length}`);
    console.log('пересоберите сайт: node build_gate.mjs');
    return;
  }

  const login = (positional[0] || '').trim();
  if (!login) {
    console.error('Укажите логин: node add_user.mjs <логин>');
    process.exit(1);
  }

  if (flags.includes('--remove')) {
    const rest = users.filter(u => u.login !== login);
    if (rest.length === users.length) { console.error('такого логина нет'); process.exit(1); }
    saveUsers(rest);
    console.log(`логин «${login}» удалён — не забудьте пересобрать: node build_gate.mjs`);
    return;
  }

  let password = process.env.LP_PASSWORD || '';
  if (!password) {
    password = await askHidden(`Пароль для «${login}» (не отображается): `);
    const again = await askHidden('Повторите пароль: ');
    if (password !== again) { console.error('пароли не совпали'); process.exit(1); }
  }
  if (password.length < 4) { console.error('пароль слишком короткий'); process.exit(1); }

  const record = userRecord(login, password, { name: flagValue('--name'), inherit: flags.includes('--inherit') });
  const i = users.findIndex(u => u.login === login);
  if (i >= 0) users[i] = record; else users.push(record);
  saveUsers(users);
  console.log(`логин «${login}» ${i >= 0 ? 'обновлён' : 'добавлен'} — ${users.length} всего`);
  console.log('пересоберите сайт: node build_gate.mjs');
}

main().catch(e => { console.error(e.message); process.exit(1); });