/**
 * The passkey unlock page: a tab of its own where the browser's passkey
 * prompt runs. The URL hash picks what it does:
 *
 *   #unlock        open a locked vault with an enrolled passkey, or with the
 *                  PIN or passphrase
 *   #enroll        add a passkey that unlocks the vault
 *   #reset-secret  set a new PIN or passphrase, authorized by a passkey
 *
 * The page only runs WebAuthn (unlock-passkey-client.ts) and passes the PRF
 * output to the background, over the channel the PIN already uses. The
 * background derives, unwraps and installs; the vault's data key never
 * reaches a page. A prompt runs outside the background's queues, so every
 * commit can come back refused (locked meanwhile, lock changed meanwhile)
 * and the page says so.
 *
 * One prompt at a time across tabs, through a Web Lock held for the prompt
 * and its commit. Nothing about that is kept in the background, so a
 * restarted worker cannot leave a stale marker.
 */

import { initAndLocalize, t } from '../i18n';
import { initTheme } from '../theme';
import { checkVaultSecret, isPin } from '../crypto/vault-secret';
import { isPasskeyUnlockOrigin, type UnlockPasskeyInfo } from '../crypto/unlock-record';
import { uint8ArrayToBase64 } from '../utils/base64';
import {
  confirmUnlockPasskey,
  createUnlockPasskey,
  readUnlockPrf,
  UnlockCeremonyError,
  type CeremonyFailure,
  type CreatedUnlockPasskey,
} from './unlock-passkey-client';

type Mode = 'unlock' | 'enroll' | 'reset-secret';
type View = 'unlock-view' | 'enroll-view' | 'reset-view' | 'unavailable-view';

interface UnlockMethods {
  isSetup: boolean;
  isUnlocked: boolean;
  supported: boolean;
  format: string;
  vaultId: string | null;
  passkeys: UnlockPasskeyInfo[];
  damagedPasskeys: number;
  max: number;
  /** An upgraded vault that takes no change to its lock until backed up. */
  backupRequired: boolean;
}

interface BackgroundResponse {
  success: boolean;
  code?: string;
  [key: string]: unknown;
}

/** A passkey created at the provider and not yet confirmed or stored. */
interface PendingEnrollment {
  secret: string;
  name: string;
  vaultId: string;
  created: CreatedUnlockPasskey;
}

/** A failure whose message is already the text to show. */
class Shown extends Error {}

const CEREMONY_LOCK = 'passkey-bond-unlock-ceremony';
/** A PIN shorter than this gets the stronger warning at enrollment. */
const STRONG_PIN_DIGITS = 10;
const VIEWS: View[] = ['unlock-view', 'enroll-view', 'reset-view', 'unavailable-view'];

function modeFromHash(): Mode {
  const hash = window.location.hash.replace(/^#/, '');
  return hash === 'enroll' || hash === 'reset-secret' ? hash : 'unlock';
}

/** The tab closes itself after an unlock only when it was opened to unlock. */
const loadedMode = modeFromHash();
let mode: Mode = loadedMode;
let methods: UnlockMethods | null = null;
let busy = false;
let fallbackOpen = false;
let pending: PendingEnrollment | null = null;
let enrolledName: string | null = null;
let resetDone = false;

function el<T extends HTMLElement = HTMLElement>(id: string): T {
  return document.getElementById(id) as T;
}

function setText(id: string, text: string): void {
  const node = el(id);
  node.textContent = text;
  node.hidden = text === '';
}

function clearMessages(): void {
  for (const id of ['unlock', 'enroll', 'reset']) {
    setText(`${id}-status`, '');
    setText(`${id}-error`, '');
  }
}

async function send(type: string, payload?: Record<string, unknown>): Promise<BackgroundResponse> {
  try {
    const response = await chrome.runtime.sendMessage({ type, payload });
    return response && typeof response === 'object' ? response : { success: false };
  } catch {
    return { success: false };
  }
}

async function loadMethods(): Promise<UnlockMethods | null> {
  const response = await send('GET_UNLOCK_METHODS');
  if (!response.success) return null;
  return {
    isSetup: response.isSetup === true,
    isUnlocked: response.isUnlocked === true,
    supported: response.supported === true,
    format: String(response.format ?? ''),
    vaultId: typeof response.vaultId === 'string' ? response.vaultId : null,
    passkeys: Array.isArray(response.passkeys) ? (response.passkeys as UnlockPasskeyInfo[]) : [],
    damagedPasskeys: Number(response.damagedPasskeys) || 0,
    max: Number(response.max) || 0,
    backupRequired: response.backupRequired === true,
  };
}

/** Whether this page can show a passkey prompt at all. */
function pageSupportsPasskeys(): boolean {
  return (
    isPasskeyUnlockOrigin(chrome.runtime.getURL('')) &&
    typeof PublicKeyCredential !== 'undefined' &&
    !!navigator.credentials
  );
}

function codeMessage(code: unknown): string {
  switch (code) {
    case 'VAULT_LOCKED':
      return t('unlockErrVaultLocked');
    case 'UNSUPPORTED_KDF':
      return t('popupVaultNeedsUpdate');
    case 'VAULT_DAMAGED':
      return t('popupVaultDamaged');
    case 'VAULT_WRITE_UNVERIFIED':
      return t('popupVaultWriteUnverified');
    case 'UPGRADE_BACKUP_REQUIRED':
      return t('unlockErrBackupRequired');
    case 'WRONG_SECRET':
      return t('popupWrongPassword');
    case 'UNLOCK_PASSKEY_UNKNOWN':
      return t('unlockErrPasskeyUnknown');
    case 'UNLOCK_PASSKEY_MISMATCH':
      return t('unlockErrPasskeyMismatch');
    case 'UNLOCK_PASSKEY_DUPLICATE':
      return t('unlockErrPasskeyDuplicate');
    case 'UNLOCK_PASSKEY_LIMIT':
      return t('unlockErrPasskeyLimit', { max: methods?.max || 8 });
    case 'VAULT_CHANGED':
      return t('unlockErrVaultChanged');
    case 'VAULT_FORMAT_PENDING':
      return t('unlockErrFormatPending');
    case 'PASSKEY_UNLOCK_UNSUPPORTED':
      return t('unlockErrUnsupported');
    default:
      return t('unlockErrGeneric');
  }
}

function ceremonyMessage(reason: CeremonyFailure, enrolling: boolean): string {
  switch (reason) {
    case 'cancelled':
      return t('unlockErrCancelled');
    case 'no-prf':
      return enrolling ? t('unlockErrNoPrfEnroll') : t('unlockErrNoPrfUnlock');
    case 'prf-unstable':
      return t('unlockErrPrfUnstable');
    case 'excluded':
      return t('unlockErrExcluded');
    case 'unsupported':
      return t('unlockErrUnsupported');
    default:
      return t('unlockErrGeneric');
  }
}

function failureMessage(error: unknown, enrolling: boolean): string {
  if (error instanceof Shown) return error.message;
  if (error instanceof UnlockCeremonyError) return ceremonyMessage(error.reason, enrolling);
  return t('unlockErrGeneric');
}

/**
 * Run one prompt and its commit while holding the cross-tab lock. A second
 * tab is told another prompt is open instead of queueing behind it.
 */
async function withCeremonyLock<T>(job: () => Promise<T>): Promise<T> {
  const locks = navigator.locks;
  if (!locks?.request) return job(); // no Web Locks: the busy flag is all there is
  return locks.request(CEREMONY_LOCK, { ifAvailable: true }, async (lock) => {
    if (!lock) throw new Shown(t('unlockErrBusy'));
    return job();
  });
}

/** One action at a time on this page; its controls are disabled meanwhile. */
async function run(job: () => Promise<void>): Promise<void> {
  if (busy) return;
  busy = true;
  render();
  try {
    await job();
  } finally {
    busy = false;
    render();
  }
}

function dropPending(): void {
  pending?.created.createOutput?.fill(0);
  pending = null;
}

// ---------- Rendering ----------

function show(view: View): void {
  for (const id of VIEWS) el(id).hidden = id !== view;
}

function showUnavailable(text: string): void {
  el('unavailable-text').textContent = text;
  show('unavailable-view');
}

/**
 * Show what the current mode and vault state allow. Leaves typed values and
 * status or error text alone, so it is safe to call whenever the state may
 * have changed (the tab regains focus, an action ends).
 */
function render(): void {
  if (!methods) {
    showUnavailable(t('unlockErrGeneric'));
    return;
  }
  if (!methods.isSetup) {
    showUnavailable(t('optionsPasskeySetSecretFirst'));
    return;
  }
  const canUsePasskeys = methods.supported && pageSupportsPasskeys();

  if (mode === 'unlock') {
    renderUnlock(canUsePasskeys && methods.passkeys.length > 0);
    return;
  }

  // A finished enrollment or reset keeps its result on screen.
  if (mode === 'enroll' && enrolledName !== null) {
    el('enroll-form').hidden = true;
    el('enroll-done').hidden = false;
    el('enroll-done-text').textContent = t('unlockEnrollDone', { name: enrolledName });
    show('enroll-view');
    return;
  }
  if (mode === 'reset-secret' && resetDone) {
    el('reset-form').hidden = true;
    show('reset-view');
    return;
  }

  if (!canUsePasskeys) {
    showUnavailable(t('unlockErrUnsupported'));
  } else if (!methods.isUnlocked && !busy) {
    showUnavailable(t('unlockNeedsUnlocked'));
  } else if (methods.backupRequired && !pending && !busy) {
    // Said before any form is filled in: the background would refuse the
    // change after the passkey prompt.
    showUnavailable(t('unlockErrBackupRequired'));
  } else if (mode === 'enroll') {
    renderEnroll();
  } else if (methods.passkeys.length === 0) {
    showUnavailable(t('unlockNoPasskey'));
  } else {
    el('reset-form').hidden = false;
    setFormDisabled('reset-form', busy);
    show('reset-view');
  }
}

function renderUnlock(hasPasskey: boolean): void {
  const unlocked = methods?.isUnlocked === true;
  // Without a passkey the PIN or passphrase form is the whole screen.
  const formOpen = !unlocked && (fallbackOpen || !hasPasskey);
  const toggle = el<HTMLButtonElement>('fallback-toggle');

  el('unlock-help').textContent = hasPasskey ? t('unlockHelp') : t('popupUnlockHelp');
  el('unlock-help').hidden = unlocked;
  el('passkey-unlock-btn').hidden = unlocked || !hasPasskey;
  toggle.hidden = unlocked || !hasPasskey || fallbackOpen;
  toggle.setAttribute('aria-expanded', String(formOpen));
  el('fallback-form').hidden = !formOpen;
  el<HTMLButtonElement>('passkey-unlock-btn').disabled = busy;
  toggle.disabled = busy;
  setFormDisabled('fallback-form', busy);
  if (unlocked) {
    setText('unlock-error', '');
    setText('unlock-status', t('unlockUnlocked'));
  } else if (!busy && el('unlock-status').textContent === t('unlockUnlocked')) {
    setText('unlock-status', ''); // locked again since
  }
  show('unlock-view');
}

function renderEnroll(): void {
  if (!pending && !busy) {
    if (methods.format === 'legacy') {
      showUnavailable(t('unlockErrFormatPending'));
      return;
    }
    if (methods.max > 0 && methods.passkeys.length >= methods.max) {
      showUnavailable(t('unlockErrPasskeyLimit', { max: methods.max }));
      return;
    }
  }
  const nameInput = el<HTMLInputElement>('enroll-name');
  if (!nameInput.value && !pending) {
    nameInput.value = t('unlockDefaultName', { n: methods.passkeys.length + 1 });
  }
  el('enroll-form').hidden = false;
  el('enroll-done').hidden = true;
  // Once the passkey exists at the provider, the only step left is confirming
  // it: the secret is already checked and held, so its field goes away.
  el('enroll-secret-group').hidden = !!pending;
  el<HTMLInputElement>('enroll-secret').disabled = busy || !!pending;
  nameInput.disabled = busy || !!pending;
  el('enroll-create-btn').hidden = !!pending;
  el('enroll-confirm-btn').hidden = !pending;
  el<HTMLButtonElement>('enroll-create-btn').disabled = busy;
  el<HTMLButtonElement>('enroll-confirm-btn').disabled = busy;
  show('enroll-view');
}

function setFormDisabled(formId: string, disabled: boolean): void {
  el(formId)
    .querySelectorAll<HTMLInputElement | HTMLButtonElement>('input, button')
    .forEach((control) => (control.disabled = disabled));
}

async function refresh(): Promise<void> {
  methods = await loadMethods();
  render();
}

function focusFirstAction(): void {
  const view = VIEWS.map((id) => el(id)).find((node) => !node.hidden);
  const target = Array.from(view?.querySelectorAll<HTMLElement>('input, button') ?? []).find(
    (node) => !node.hidden && !node.closest('[hidden]') && !(node as HTMLInputElement).disabled
  );
  target?.focus();
}

async function enterMode(next: Mode): Promise<void> {
  mode = next;
  dropPending();
  enrolledName = null;
  resetDone = false;
  fallbackOpen = false;
  clearMessages();
  for (const id of ['fallback-secret', 'enroll-secret', 'enroll-name']) {
    el<HTMLInputElement>(id).value = '';
  }
  for (const id of ['reset-secret-new', 'reset-secret-confirm']) {
    el<HTMLInputElement>(id).value = '';
  }
  el('enroll-short-pin-warning').hidden = true;
  await refresh();
  focusFirstAction();
}

// ---------- Unlock ----------

async function closeThisTab(): Promise<void> {
  try {
    const tab = await chrome.tabs.getCurrent();
    if (tab?.id !== undefined) await chrome.tabs.remove(tab.id);
  } catch {
    // Not a tab, or it cannot be closed: the page says the vault is unlocked.
  }
}

async function afterUnlock(): Promise<void> {
  el<HTMLInputElement>('fallback-secret').value = '';
  await refresh();
  if (loadedMode === 'unlock' && methods?.isUnlocked) await closeThisTab();
}

function unlockWithPasskey(): Promise<void> {
  return run(async () => {
    clearMessages();
    setText('unlock-status', t('unlockWaiting'));
    try {
      await withCeremonyLock(async () => {
        // The list may have changed since this page was drawn.
        const fresh = await loadMethods();
        if (!fresh) throw new Shown(t('unlockErrGeneric'));
        methods = fresh;
        if (fresh.isUnlocked) return;
        if (fresh.passkeys.length === 0) throw new Shown(t('unlockNoPasskey'));

        const { credentialId, prfOutput } = await readUnlockPrf(
          navigator.credentials,
          fresh.passkeys
        );
        const payload = { credentialId, prfOutput: uint8ArrayToBase64(prfOutput) };
        prfOutput.fill(0);
        const response = await send('UNLOCK_WITH_PASSKEY', payload);
        if (!response.success) throw new Shown(codeMessage(response.code));
      });
      setText('unlock-status', '');
      await afterUnlock();
    } catch (error) {
      setText('unlock-status', '');
      setText('unlock-error', failureMessage(error, false));
    }
  });
}

function unlockWithSecret(): Promise<void> {
  return run(async () => {
    const input = el<HTMLInputElement>('fallback-secret');
    const password = input.value;
    clearMessages();
    if (!password) {
      setText('unlock-error', t('unlockSecretRequired'));
      return;
    }
    setText('unlock-status', t('popupUnlocking'));
    const response = await send('UNLOCK_SECURE_STORAGE', { password });
    setText('unlock-status', '');
    if (response.success) {
      await afterUnlock();
      return;
    }
    input.value = '';
    setText(
      'unlock-error',
      response.code === 'UNSUPPORTED_KDF' ||
        response.code === 'VAULT_DAMAGED' ||
        response.code === 'VAULT_WRITE_UNVERIFIED'
        ? codeMessage(response.code)
        : t('popupWrongPassword')
    );
  }).then(() => {
    if (!el('fallback-form').hidden) el('fallback-secret').focus();
  });
}

// ---------- Enrollment ----------

/** Step one: check the secret, then create the passkey at the provider. */
function createPasskey(): Promise<void> {
  return run(async () => {
    const secret = el<HTMLInputElement>('enroll-secret').value;
    const name = el<HTMLInputElement>('enroll-name').value.trim();
    clearMessages();
    if (!secret) {
      setText('enroll-error', t('unlockSecretRequired'));
      return;
    }
    if (!name) {
      setText('enroll-error', t('unlockEnrollNameRequired'));
      return;
    }
    setText('enroll-status', t('unlockEnrollVerifying'));
    try {
      await withCeremonyLock(async () => {
        const fresh = await loadMethods();
        if (!fresh) throw new Shown(t('unlockErrGeneric'));
        methods = fresh;
        // Found before any prompt opened, unlike a refusal from the background.
        if (!fresh.isUnlocked) throw new Shown(t('unlockNeedsUnlocked'));
        // A passkey created now would be refused when it is stored, and
        // would stay behind at the provider.
        if (fresh.backupRequired) throw new Shown(codeMessage('UPGRADE_BACKUP_REQUIRED'));
        if (fresh.format === 'legacy') throw new Shown(codeMessage('VAULT_FORMAT_PENDING'));
        if (!fresh.vaultId) throw new Shown(codeMessage('VAULT_DAMAGED'));

        // Before any prompt, so a mistyped secret cannot leave a passkey at
        // the provider that the vault never learns about.
        const verified = await send('VERIFY_MASTER_PASSWORD', { password: secret });
        if (!verified.success) throw new Shown(codeMessage(verified.code));
        if (verified.valid !== true) throw new Shown(t('popupWrongPassword'));

        setText('enroll-status', t('unlockWaiting'));
        const created = await createUnlockPasskey(navigator.credentials, {
          name,
          excludeCredentialIds: fresh.passkeys.map((passkey) => passkey.credentialId),
        });
        pending = { secret, name, vaultId: fresh.vaultId, created };
      });
      el<HTMLInputElement>('enroll-secret').value = '';
      setText('enroll-status', t('unlockEnrollCreated'));
    } catch (error) {
      setText('enroll-status', '');
      setText('enroll-error', failureMessage(error, true));
    }
  }).then(() => {
    if (pending) el('enroll-confirm-btn').focus();
  });
}

/** Step two: read the PRF output as an unlock will, then store the passkey. */
function confirmPasskey(): Promise<void> {
  return run(async () => {
    if (!pending) return;
    const enrollment = pending;
    clearMessages();
    setText('enroll-status', t('unlockWaiting'));
    try {
      await withCeremonyLock(async () => {
        const prfOutput = await confirmUnlockPasskey(navigator.credentials, enrollment.created);
        const payload = {
          password: enrollment.secret,
          vaultId: enrollment.vaultId,
          credentialId: enrollment.created.credentialId,
          prfSalt: enrollment.created.prfSalt,
          prfOutput: uint8ArrayToBase64(prfOutput),
          name: enrollment.name,
          transports: enrollment.created.transports,
        };
        prfOutput.fill(0);
        setText('enroll-status', t('unlockSaving'));
        const response = await send('ENROLL_UNLOCK_PASSKEY', payload);
        if (!response.success) throw new Shown(codeMessage(response.code));
        const stored = response.passkey as UnlockPasskeyInfo | undefined;
        enrolledName = typeof stored?.name === 'string' ? stored.name : enrollment.name;
      });
      dropPending();
      el<HTMLInputElement>('enroll-name').value = '';
      el('enroll-short-pin-warning').hidden = true;
      setText('enroll-status', '');
      methods = (await loadMethods()) ?? methods;
    } catch (error) {
      setText('enroll-status', '');
      setText('enroll-error', failureMessage(error, true));
      // A dismissed prompt can be answered again. Anything else ends this
      // enrollment: nothing was stored, and the passkey just created may
      // remain at the provider.
      const retry = error instanceof UnlockCeremonyError && error.reason === 'cancelled';
      if (!retry) dropPending();
    }
  }).then(() => {
    if (enrolledName !== null) el('enroll-again-btn').focus();
    else if (pending) el('enroll-confirm-btn').focus();
  });
}

function showShortPinWarning(): void {
  const secret = el<HTMLInputElement>('enroll-secret').value;
  el('enroll-short-pin-warning').hidden = !(isPin(secret) && secret.length < STRONG_PIN_DIGITS);
}

// ---------- New PIN or passphrase, authorized by a passkey ----------

function resetSecret(): Promise<void> {
  return run(async () => {
    const next = el<HTMLInputElement>('reset-secret-new').value;
    clearMessages();
    const problem = checkVaultSecret(next);
    if (problem) {
      setText(
        'reset-error',
        problem === 'too-long' ? t('vaultSecretTooLong') : t('popupPasswordMin')
      );
      return;
    }
    if (next !== el<HTMLInputElement>('reset-secret-confirm').value) {
      setText('reset-error', t('unlockSecretsNoMatch'));
      return;
    }
    setText('reset-status', t('unlockWaiting'));
    try {
      await withCeremonyLock(async () => {
        const fresh = await loadMethods();
        if (!fresh) throw new Shown(t('unlockErrGeneric'));
        methods = fresh;
        // Found before any prompt opened, unlike a refusal from the background.
        if (!fresh.isUnlocked) throw new Shown(t('unlockNeedsUnlocked'));
        if (fresh.backupRequired) throw new Shown(codeMessage('UPGRADE_BACKUP_REQUIRED'));
        if (fresh.passkeys.length === 0) throw new Shown(t('unlockNoPasskey'));

        const { credentialId, prfOutput } = await readUnlockPrf(
          navigator.credentials,
          fresh.passkeys
        );
        const payload = {
          credentialId,
          prfOutput: uint8ArrayToBase64(prfOutput),
          newPassword: next,
        };
        prfOutput.fill(0);
        setText('reset-status', t('unlockSaving'));
        const response = await send('CHANGE_MASTER_PASSWORD_WITH_PASSKEY', payload);
        if (!response.success) throw new Shown(codeMessage(response.code));
      });
      el<HTMLInputElement>('reset-secret-new').value = '';
      el<HTMLInputElement>('reset-secret-confirm').value = '';
      resetDone = true;
      setText('reset-status', t('unlockResetDone'));
    } catch (error) {
      setText('reset-status', '');
      setText('reset-error', failureMessage(error, false));
    }
  });
}

// ---------- Wiring ----------

document.addEventListener('DOMContentLoaded', async () => {
  await Promise.all([initAndLocalize(), initTheme()]);

  el('passkey-unlock-btn').addEventListener('click', () => void unlockWithPasskey());
  el('fallback-toggle').addEventListener('click', () => {
    fallbackOpen = true;
    render();
    el('fallback-secret').focus();
  });
  el('fallback-form').addEventListener('submit', (event) => {
    event.preventDefault();
    void unlockWithSecret();
  });

  el('enroll-form').addEventListener('submit', (event) => {
    event.preventDefault();
    if (!pending) void createPasskey();
  });
  el('enroll-confirm-btn').addEventListener('click', () => void confirmPasskey());
  el('enroll-again-btn').addEventListener('click', () => void enterMode('enroll'));
  el('enroll-secret').addEventListener('input', showShortPinWarning);

  el('reset-form').addEventListener('submit', (event) => {
    event.preventDefault();
    void resetSecret();
  });

  window.addEventListener('hashchange', () => void enterMode(modeFromHash()));
  // The vault can lock or unlock elsewhere while this tab sits in the
  // background; look again when it comes back.
  const recheck = () => {
    if (!busy && document.visibilityState === 'visible') void refresh();
  };
  window.addEventListener('focus', recheck);
  document.addEventListener('visibilitychange', recheck);

  await enterMode(mode);
});
