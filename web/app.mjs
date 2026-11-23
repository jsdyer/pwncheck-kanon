import { checkPassword, validateConfig } from './model.mjs';

const form = document.querySelector('#check-form');
const password = document.querySelector('#password');
const check = document.querySelector('#check');
const show = document.querySelector('#show-password');
const clear = document.querySelector('#clear');
const result = document.querySelector('#result');
const title = document.querySelector('#result-title');
const detail = document.querySelector('#result-detail');
const count = document.querySelector('#result-count');
const status = document.querySelector('#status');
let config;
let active;
let generation = 0;

function resetResult() {
  result.hidden = true;
  result.removeAttribute('data-state');
  title.textContent = '';
  detail.textContent = '';
  count.textContent = '';
}
function cancel() {
  generation++;
  active?.abort();
  active = undefined;
  check.disabled = !config;
  check.textContent = 'Check exposure';
  form.removeAttribute('aria-busy');
}
function reset() {
  cancel();
  password.value = '';
  password.type = 'password';
  show.setAttribute('aria-pressed', 'false');
  show.textContent = 'Show';
  resetResult();
  status.textContent = config ? 'Cleared. No password or result is saved by this tool.' : 'Loading checker settings…';
}
password.addEventListener('input', () => {
  cancel();
  resetResult();
  status.textContent = 'Ready when you are. Nothing is checked while you type.';
});
show.addEventListener('click', () => {
  const visible = password.type === 'password';
  password.type = visible ? 'text' : 'password';
  show.setAttribute('aria-pressed', String(visible));
  show.textContent = visible ? 'Hide' : 'Show';
});
clear.addEventListener('click', () => { reset(); password.focus(); });
window.addEventListener('pagehide', reset);
window.addEventListener('pageshow', event => { if (event.persisted) reset(); });

form.addEventListener('submit', async event => {
  event.preventDefault();
  if (!config || check.disabled) return;
  cancel();
  resetResult();
  const attempt = generation;
  const controller = new AbortController();
  active = controller;
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; controller.abort(); }, config.timeoutMs);
  check.disabled = true;
  check.textContent = 'Checking…';
  form.setAttribute('aria-busy', 'true');
  status.textContent = 'Hashing in this browser, then requesting a padded range of possible matches…';
  try {
    const answer = await checkPassword(password.value, config, { signal: controller.signal });
    if (attempt !== generation) return;
    password.value = ''; // Minimize retention; never render a secret or hash.
    password.type = 'password';
    show.setAttribute('aria-pressed', 'false');
    show.textContent = 'Show';
    result.dataset.state = answer.found ? 'found' : 'absent';
    title.textContent = answer.found ? 'Found in the breach dataset' : 'No match in this dataset';
    count.textContent = answer.found ? `${answer.count.toLocaleString()} recorded occurrences` : 'A limited result, not an all-clear';
    detail.textContent = answer.found
      ? 'This password appears in known exposed-password data. If you use it, replace it wherever it is used with a unique password. This does not identify a breached account or when a breach happened.'
      : 'This password was not in the returned Pwned Passwords range. It could still be weak, reused, or exposed in data the service has not collected. This is not proof that it is safe.';
    result.hidden = false;
    status.textContent = 'Check complete. The input was cleared; the result stays only in this tab.';
  } catch (error) {
    if (attempt !== generation) return;
    status.textContent = timedOut ? 'The check timed out. No exposure result is available. Try again later.'
      : error instanceof TypeError ? 'The provider could not be reached. No exposure result is available. Check your connection and try again later.'
      : error.name === 'AbortError' ? 'Check cancelled. No exposure result is available.' : error.message;
  } finally {
    clearTimeout(timer);
    if (attempt === generation) {
      active = undefined;
      check.disabled = !config;
      check.textContent = 'Check exposure';
      form.removeAttribute('aria-busy');
    }
  }
});

try {
  const response = await fetch('./config.json', { credentials: 'omit', cache: 'no-store' });
  if (!response.ok) throw new Error();
  config = validateConfig(await response.json());
  check.disabled = false;
  document.querySelector('#input-limit').textContent = `Up to ${config.maxPasswordBytes.toLocaleString()} UTF-8 bytes. Spaces and capitalization are preserved.`;
  status.textContent = 'Ready when you are. Nothing is checked while you type.';
} catch {
  status.textContent = 'The checker settings could not load. Refresh the page to try again. No password has been checked.';
}
