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
import { cleanPasskeyName } from '../crypto/passkey-name';
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
/** The typed PIN or passphrase was not the vault's: shown under its field. */
class WrongSecret extends Shown {}

const CEREMONY_LOCK = 'passkey-bond-unlock-ceremony';
/** A PIN shorter than this gets the stronger warning at enrollment. */
const STRONG_PIN_DIGITS = 10;
/** The shackle of the lock icon at the top of the page, closed and open. */
const SHACKLE_CLOSED = 'M7 11V7a5 5 0 0 1 10 0v4';
const SHACKLE_OPEN = 'M7 11V7a5 5 0 0 1 9.9-1';
const VIEWS: View[] = ['unlock-view', 'enroll-view', 'reset-view', 'unavailable-view'];

function modeFromHash(): Mode {
  const hash = window.location.hash.replace(/^#/, '');
  return hash === 'enroll' || hash === 'reset-secret' ? hash : 'unlock';
}

/** The tab closes itself after an unlock only when it was opened to unlock. */
const loadedMode = modeFromHash();
const params = new URLSearchParams(window.location.search);
/**
 * Opened by the popup in a small window of its own (?window=<id of the
 * browser window it came from>) rather than a tab. Its close buttons say
 * "Close", and an unlock goes back to the popup.
 */
const inWindow = params.has('window');
const originWindowId = Number.parseInt(params.get('window') ?? '', 10);
/** Start the passkey prompt as soon as the page is ready (?start=1). */
const startPrompt = params.get('start') === '1';
if (inWindow) document.documentElement.classList.add('in-window');
let mode: Mode = loadedMode;
let methods: UnlockMethods | null = null;
let busy = false;
let fallbackOpen = false;
let pending: PendingEnrollment | null = null;
let enrolledName: string | null = null;
let resetDone = false;
/** The secret typed for enrollment was refused and has not been retyped. */
let secretRefused = false;
/** What the button on the unavailable view does. */
let unavailableWay: 'close' | 'settings' = 'close';

function el<T extends HTMLElement = HTMLElement>(id: string): T {
  return document.getElementById(id) as T;
}

function setText(id: string, text: string): void {
  const node = el(id);
  node.textContent = text;
  node.hidden = text === '';
}

/**
 * Show an error directly under the field or button it is about. Each view
 * has one error element, which is moved to that control.
 */
function showError(id: string, text: string, underId: string): void {
  const node = el(id);
  el(underId).after(node);
  setText(id, text);
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
    // A mode change asked for meanwhile waited for the action to end.
    if (modeFromHash() !== mode) void enterMode(modeFromHash());
  }
}

function dropPending(): void {
  pending?.created.createOutput?.fill(0);
  pending = null;
}

// ---------- Rendering ----------

function show(view: View, lockOpen = false): void {
  for (const id of VIEWS) el(id).hidden = id !== view;
  document
    .getElementById('lock-shackle')
    ?.setAttribute('d', lockOpen ? SHACKLE_OPEN : SHACKLE_CLOSED);
}

function modeHeading(): string {
  if (mode === 'enroll') return t('unlockEnrollHeading');
  return mode === 'reset-secret' ? t('unlockResetHeading') : t('unlockHeading');
}

/**
 * Say why the page cannot do what it was opened for, under that heading,
 * with the one thing left to do: close the tab, or go and set a lock.
 */
function showUnavailable(text: string, way: 'close' | 'settings' = 'close'): void {
  unavailableWay = way;
  el('unavailable-title').textContent = modeHeading();
  el('unavailable-text').textContent = text;
  el('unavailable-action-btn').textContent =
    way === 'settings' ? t('unlockOpenSecuritySettings') : closeLabel();
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
    showUnavailable(t('optionsPasskeySetSecretFirst'), 'settings');
    return;
  }
  const canUsePasskeys = methods.supported && pageSupportsPasskeys();
  const hasPasskey = canUsePasskeys && methods.passkeys.length > 0;

  if (mode === 'unlock') {
    renderUnlock(hasPasskey, null);
    return;
  }

  // A finished enrollment or reset keeps its result on screen, under a
  // heading that says so and without the instructions for getting there.
  const enrolled = mode === 'enroll' && enrolledName !== null;
  el('enroll-title').textContent = enrolled
    ? t('unlockEnrollDoneHeading')
    : t('unlockEnrollHeading');
  el('enroll-help').hidden = enrolled;
  el('enroll-done').hidden = !enrolled;
  if (enrolled) {
    el('enroll-form').hidden = true;
    el('enroll-done-text').textContent = t('unlockEnrollDone', { name: enrolledName });
    show('enroll-view');
    return;
  }
  const wasReset = mode === 'reset-secret' && resetDone;
  el('reset-title').textContent = wasReset ? t('unlockResetDone') : t('unlockResetHeading');
  el('reset-help').hidden = wasReset;
  el('reset-done').hidden = !wasReset;
  if (wasReset) {
    el('reset-form').hidden = true;
    show('reset-view');
    return;
  }

  // An action that began on another view keeps that view while it runs,
  // even if the vault locks under it; its commit reports the lock.
  const onUnlockView = !el('unlock-view').hidden;
  if (!canUsePasskeys) {
    showUnavailable(t('unlockErrUnsupported'));
  } else if (!methods.isUnlocked && (!busy || onUnlockView)) {
    // Locked: unlock right here, then carry on with what the page was
    // opened for.
    if (mode === 'reset-secret' && !hasPasskey) {
      // Only a passkey can take this further, and there is none to ask.
      showUnavailable(t('unlockNoPasskey'));
    } else {
      renderUnlock(hasPasskey, mode);
    }
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

/**
 * The lock screen. `step` is the mode that needs the vault unlocked first, if
 * that is why it shows: the line above the controls then says what follows.
 * Someone setting a new PIN or passphrase has forgotten the old one, so that
 * step offers the passkey alone, and closing the tab as the way out.
 */
function renderUnlock(hasPasskey: boolean, step: Mode | null): void {
  const unlocked = methods?.isUnlocked === true;
  const passkeyOnly = step === 'reset-secret';
  // Without a passkey the PIN or passphrase form is the whole screen.
  const formOpen = !unlocked && !passkeyOnly && (fallbackOpen || !hasPasskey);
  const toggle = el<HTMLButtonElement>('fallback-toggle');
  const secretBtn = el<HTMLButtonElement>('fallback-unlock-btn');

  el('unlock-title').textContent = unlocked ? t('unlockUnlocked') : t('unlockHeading');
  // The two buttons say what they do; a line above them is only for what
  // they do not say.
  el('unlock-help').textContent =
    step === 'enroll'
      ? t('unlockNeedsUnlockedEnroll')
      : step === 'reset-secret'
        ? t('unlockNeedsUnlockedReset')
        : t('popupUnlockHelp');
  el('unlock-help').hidden = unlocked || (hasPasskey && !step);
  // The way on once unlocked; the way out where only the passkey is offered.
  const closeBtn = el('unlock-close-btn');
  closeBtn.hidden = !unlocked && !passkeyOnly;
  closeBtn.classList.toggle('btn-primary', unlocked);
  closeBtn.classList.toggle('btn-ghost', !unlocked);
  // The only action is the main one.
  secretBtn.classList.toggle('btn-primary', !hasPasskey);
  secretBtn.classList.toggle('btn-secondary', hasPasskey);
  el('passkey-unlock-btn').hidden = unlocked || !hasPasskey;
  toggle.hidden = unlocked || !hasPasskey || fallbackOpen || passkeyOnly;
  toggle.setAttribute('aria-expanded', String(formOpen));
  el('fallback-form').hidden = !formOpen;
  el<HTMLButtonElement>('passkey-unlock-btn').disabled = busy;
  toggle.disabled = busy;
  setFormDisabled('fallback-form', busy);
  if (unlocked) {
    setText('unlock-error', '');
    setText('unlock-status', '');
  }
  show('unlock-view', unlocked);
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
  // Once the passkey exists at the provider, the only step left is confirming
  // it: the secret is already checked and held, so its field goes away.
  el('enroll-secret-group').hidden = !!pending;
  showShortPinWarning();
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
  secretRefused = false;
  fallbackOpen = false;
  clearMessages();
  for (const id of ['fallback-secret', 'enroll-secret', 'enroll-name']) {
    el<HTMLInputElement>(id).value = '';
  }
  for (const id of ['reset-secret-new', 'reset-secret-confirm']) {
    el<HTMLInputElement>(id).value = '';
  }
  await refresh();
  // Tells a test, or anything else watching, that this mode is on screen.
  if (mode === next) document.body.dataset.mode = next;
  focusFirstAction();
}

// ---------- Unlock ----------

function closeLabel(): string {
  return inWindow ? t('commonClose') : t('unlockCloseTab');
}

/** Closes the window too, when the page is its only tab. */
async function closeThisTab(): Promise<void> {
  try {
    const tab = await chrome.tabs.getCurrent();
    if (tab?.id !== undefined) await chrome.tabs.remove(tab.id);
  } catch {
    // Not a tab, or it cannot be closed: the page says the vault is unlocked.
  }
}

/**
 * Back to the popup the user came from, now unlocked, where the browser
 * lets an extension open its popup (Chrome 127 and later).
 */
async function reopenPopup(): Promise<void> {
  const action = chrome.action as {
    openPopup?: (options?: { windowId?: number }) => Promise<void>;
  };
  if (!Number.isInteger(originWindowId) || typeof action?.openPopup !== 'function') return;
  try {
    await chrome.windows.update(originWindowId, { focused: true });
    await action.openPopup({ windowId: originWindowId });
  } catch {
    // The window is gone, or the browser refused: the toolbar button still works.
  }
}

async function afterUnlock(): Promise<void> {
  el<HTMLInputElement>('fallback-secret').value = '';
  fallbackOpen = false;
  await refresh();
  if (!methods?.isUnlocked) return;
  if (mode === 'unlock' && loadedMode === 'unlock') {
    if (inWindow) await reopenPopup();
    await closeThisTab();
  } else {
    // Unlocked as a step towards something else, which is now on screen.
    focusFirstAction();
  }
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
      showError('unlock-error', failureMessage(error, false), 'passkey-unlock-btn');
    }
  });
}

function unlockWithSecret(): Promise<void> {
  return run(async () => {
    const input = el<HTMLInputElement>('fallback-secret');
    const password = input.value;
    clearMessages();
    if (!password) {
      showError('unlock-error', t('unlockSecretRequired'), 'fallback-secret');
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
    // With no passkey on offer there is no other unlock method to suggest.
    const noPasskey = el('passkey-unlock-btn').hidden;
    showError(
      'unlock-error',
      response.code === 'VAULT_DAMAGED' && noPasskey
        ? t('popupVaultDamagedNoPasskey')
        : response.code === 'UNSUPPORTED_KDF' ||
            response.code === 'VAULT_DAMAGED' ||
            response.code === 'VAULT_WRITE_UNVERIFIED'
          ? codeMessage(response.code)
          : t('popupWrongPassword'),
      'fallback-secret'
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
    const typedName = el<HTMLInputElement>('enroll-name').value;
    clearMessages();
    if (!secret) {
      showError('enroll-error', t('unlockSecretRequired'), 'enroll-secret');
      return;
    }
    if (!typedName.trim()) {
      showError('enroll-error', t('unlockEnrollNameRequired'), 'enroll-name');
      return;
    }
    // The background's own rule, applied before any prompt: a name it would
    // refuse afterwards would leave the new passkey behind at the provider.
    const name = cleanPasskeyName(typedName);
    if (!name) {
      showError('enroll-error', t('unlockEnrollNameInvalid'), 'enroll-name');
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
        if (verified.valid !== true) throw new WrongSecret(t('popupWrongPassword'));

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
      secretRefused = error instanceof WrongSecret;
      showError(
        'enroll-error',
        failureMessage(error, true),
        secretRefused ? 'enroll-secret' : 'enroll-create-btn'
      );
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
      setText('enroll-status', '');
      methods = (await loadMethods()) ?? methods;
    } catch (error) {
      setText('enroll-status', '');
      // A dismissed prompt can be answered again. Anything else ends this
      // enrollment: nothing was stored, and the passkey just created may
      // remain at the provider.
      const retry = error instanceof UnlockCeremonyError && error.reason === 'cancelled';
      if (!retry) dropPending();
      showError(
        'enroll-error',
        failureMessage(error, true),
        retry ? 'enroll-confirm-btn' : 'enroll-create-btn'
      );
    }
  }).then(() => {
    if (enrolledName !== null) el('enroll-close-btn').focus();
    else if (pending) el('enroll-confirm-btn').focus();
  });
}

/**
 * A short PIN typed for enrollment gets the stronger warning in place of the
 * general note, so the screen says it once. Neither applies once the secret
 * is checked and its field is gone.
 */
function showShortPinWarning(): void {
  const secret = el<HTMLInputElement>('enroll-secret').value;
  // Not for a secret the vault has just refused: it is not the vault's PIN.
  const short = !pending && !secretRefused && isPin(secret) && secret.length < STRONG_PIN_DIGITS;
  el('enroll-short-pin-warning').hidden = !short;
  // The general note gives way to the warning, and is done with once the
  // passkey exists and only confirming is left.
  el('enroll-disclosure').hidden = short || !!pending;
}

// ---------- New PIN or passphrase, authorized by a passkey ----------

function resetSecret(): Promise<void> {
  return run(async () => {
    const next = el<HTMLInputElement>('reset-secret-new').value;
    clearMessages();
    const problem = checkVaultSecret(next);
    if (problem) {
      showError(
        'reset-error',
        problem === 'too-long' ? t('vaultSecretTooLong') : t('popupPasswordMin'),
        'reset-secret-new'
      );
      return;
    }
    if (next !== el<HTMLInputElement>('reset-secret-confirm').value) {
      showError('reset-error', t('unlockSecretsNoMatch'), 'reset-secret-confirm');
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
      setText('reset-status', '');
    } catch (error) {
      setText('reset-status', '');
      showError('reset-error', failureMessage(error, false), 'reset-confirm-btn');
    }
  }).then(() => {
    if (resetDone) el('reset-close-btn').focus();
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
  el('enroll-secret').addEventListener('input', () => {
    if (secretRefused) {
      // Retyping: the refusal was about what was there before.
      secretRefused = false;
      setText('enroll-error', '');
    }
    showShortPinWarning();
  });
  for (const id of ['unlock-close-btn', 'enroll-close-btn', 'reset-close-btn']) {
    el(id).addEventListener('click', () => void closeThisTab());
  }
  el('unavailable-action-btn').addEventListener('click', () => {
    if (unavailableWay === 'settings') {
      void chrome.tabs.create({ url: chrome.runtime.getURL('options.html#security') });
    } else {
      void closeThisTab();
    }
  });
  el('fallback-secret').setAttribute('aria-label', t('unlockSecretLabel'));

  el('reset-form').addEventListener('submit', (event) => {
    event.preventDefault();
    void resetSecret();
  });

  window.addEventListener('hashchange', () => {
    // Not under a running action, which would store its result in the new
    // mode's state: run() switches once the action has ended.
    if (!busy) void enterMode(modeFromHash());
  });
  // The vault can lock or unlock elsewhere while this tab sits in the
  // background; look again when it comes back.
  const recheck = () => {
    if (!busy && document.visibilityState === 'visible') void refresh();
  };
  window.addEventListener('focus', recheck);
  document.addEventListener('visibilitychange', recheck);

  if (inWindow) {
    for (const id of ['unlock-close-btn', 'enroll-close-btn', 'reset-close-btn']) {
      el(id).textContent = closeLabel();
    }
  }

  await enterMode(mode);

  // Opened from the popup's "Unlock with passkey": that click asked for the
  // prompt, so do not ask for a second one. The browser runs a passkey
  // prompt only for a focused page, so wait for the new window's focus.
  if (startPrompt && mode === 'unlock' && !el('passkey-unlock-btn').hidden) {
    if (!document.hasFocus()) {
      await new Promise<void>((resolve) =>
        window.addEventListener('focus', () => resolve(), { once: true })
      );
    }
    if (!busy && !el('passkey-unlock-btn').hidden) void unlockWithPasskey();
  }
});
