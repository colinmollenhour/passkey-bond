/**
 * What holds around the passkey unlock page without running it: where it is
 * reachable from, what ships it, which code may touch the vault's unlock
 * record, and that every string it shows exists in every language.
 */

import { readdirSync, readFileSync, statSync } from 'fs';
import { join, resolve } from 'path';
import { translations } from '../src/i18n';

const read = (file: string) => readFileSync(resolve(file), 'utf8');
const manifests = ['src/manifest.json', 'src/manifest.firefox.json'].map(
  (file) => [file, JSON.parse(read(file))] as [string, any]
);

function page(name: string): Document {
  const doc = document.implementation.createHTMLDocument('');
  doc.documentElement.innerHTML = read(join('src/ui', name));
  return doc;
}

function sourceFiles(dir: string): string[] {
  return readdirSync(resolve(dir)).flatMap((entry) => {
    const path = join(dir, entry);
    if (statSync(resolve(path)).isDirectory()) return sourceFiles(path);
    return /\.(ts|js)$/.test(entry) ? [path] : [];
  });
}

/** Module specifiers a source file imports or requires. */
function imports(file: string): string[] {
  return [...read(file).matchAll(/(?:from|import|require\()\s*['"]([^'"]+)['"]/g)].map(
    (match) => match[1]
  );
}

const LANGUAGES = ['en', 'ru', 'zh_CN', 'ar', 'fa', 'es', 'fr'] as const;

function missingTranslations(keys: Iterable<string>): string[] {
  const missing: string[] = [];
  for (const key of new Set(keys)) {
    for (const language of LANGUAGES) {
      if (!translations[language][key]) missing.push(`${language}: ${key}`);
    }
  }
  return missing;
}

function i18nKeys(doc: ParentNode): string[] {
  const keys: string[] = [];
  for (const attribute of ['i18n', 'i18n-html', 'i18n-placeholder', 'i18n-title']) {
    doc.querySelectorAll(`[data-${attribute}]`).forEach((el) => {
      keys.push(el.getAttribute(`data-${attribute}`) as string);
    });
  }
  return keys;
}

describe('where the unlock page can be reached from', () => {
  it.each(manifests)('%s does not make it web accessible', (_file, manifest) => {
    const resources = (manifest.web_accessible_resources ?? []).flatMap(
      (entry: { resources: string[] }) => entry.resources
    );
    expect(resources.some((resource: string) => /unlock|\*/.test(resource))).toBe(false);
  });

  // On an extension page navigator.credentials must be the browser's own, so
  // neither this extension's shim nor its content script may run there.
  it.each(manifests)('%s runs no content script on extension pages', (_file, manifest) => {
    const matches: string[] = manifest.content_scripts.flatMap(
      (script: { matches: string[] }) => script.matches
    );
    expect(matches.length).toBeGreaterThan(0);
    for (const pattern of matches) {
      expect(pattern).toMatch(/^https?:\/\//);
    }
    for (const script of manifest.content_scripts) {
      expect(script.match_origin_as_fallback).toBeUndefined();
      expect(script.match_about_blank).toBeUndefined();
    }
  });

  it('is built for both browsers and required in both packages', () => {
    const build = read('build-extension.js');
    expect(build).toContain("entryPoints: ['src/ui/unlock.ts']");
    expect(build).toContain('outfile: `${distDir}/unlock.js`');
    expect(build).toContain("fs.copyFileSync('src/ui/unlock.html', `${distDir}/unlock.html`)");
    // One code path builds both targets, so nothing may make this Chrome-only.
    expect(build).not.toMatch(/isFirefox[^\n]*unlock/);

    const validate = read('scripts/validate-package.js');
    expect(validate).toContain("'unlock.html'");
    expect(validate).toContain("'unlock.js'");
    expect(JSON.parse(read('tsconfig.json')).include).toContain('src/ui/unlock.ts');
  });

  it('loads only its own script and the shared stylesheet', () => {
    const doc = page('unlock.html');
    const scripts = Array.from(doc.querySelectorAll('script'));
    expect(scripts.map((script) => script.getAttribute('src'))).toEqual(['unlock.js']);
    expect(scripts.every((script) => script.textContent === '')).toBe(true);
    expect(
      Array.from(doc.querySelectorAll('link[rel="stylesheet"]')).map((l) => l.getAttribute('href'))
    ).toEqual(['popup.css']);
  });
});

describe('what may touch the unlock record', () => {
  // Sync payloads, content scripts and the mobile app never see how the
  // vault is locked.
  it.each(['src/sync', 'src/content', 'android/web/src'])('nothing under %s imports it', (dir) => {
    const offenders = sourceFiles(dir).filter((file) =>
      imports(file).some((specifier) => /(secure-storage|unlock-record)$/.test(specifier))
    );
    expect(offenders).toEqual([]);
  });

  // src/background/prf.ts is the vault answering PRF for web sites, with its
  // own derivation. Unlocking the vault must not share code with it.
  it.each(['src/ui/unlock.ts', 'src/ui/unlock-passkey-client.ts', 'src/crypto/unlock-record.ts'])(
    '%s does not use the website authenticator',
    (file) => {
      expect(imports(file).filter((specifier) => /background\//.test(specifier))).toEqual([]);
    }
  );

  it('the page takes only the origin check and types from the unlock record', () => {
    const source = read('src/ui/unlock.ts');
    const [, names] = source.match(/import \{([^}]+)\} from '\.\.\/crypto\/unlock-record'/) ?? [];
    expect(
      names
        .split(',')
        .map((name) => name.trim())
        .sort()
    ).toEqual(['isPasskeyUnlockOrigin', 'type UnlockPasskeyInfo']);
    expect(imports('src/ui/unlock-passkey-client.ts')).toEqual(['../utils/base64']);
    // The name rule the pages share with the background brings nothing along.
    expect(imports('src/crypto/passkey-name.ts')).toEqual([]);
  });

  it('checks the name by the stored rule before the passkey is created', () => {
    const source = read('src/ui/unlock.ts');
    expect(source.indexOf('cleanPasskeyName(typedName)')).toBeGreaterThan(-1);
    expect(source.indexOf('cleanPasskeyName(typedName)')).toBeLessThan(
      source.indexOf('createUnlockPasskey(navigator.credentials')
    );
    expect(read('src/ui/options.ts')).toMatch(/cleanPasskeyName\(typed\)/);
  });

  it('knows the same transports in the page as in the record', () => {
    const list = (file: string) => read(file).match(/const TRANSPORTS = (\[[^\]]+\]);/)?.[1];
    expect(list('src/ui/unlock-passkey-client.ts')).toBeDefined();
    expect(list('src/ui/unlock-passkey-client.ts')).toBe(list('src/crypto/unlock-record.ts'));
  });
});

describe('the element IDs other pages and tests rely on', () => {
  const ids: Array<[string, string[]]> = [
    [
      'unlock.html',
      [
        'unlock-view',
        'passkey-unlock-btn',
        'unlock-status',
        'unlock-error',
        'fallback-toggle',
        'fallback-secret',
        'fallback-unlock-btn',
        'enroll-view',
        'enroll-secret',
        'enroll-name',
        'enroll-create-btn',
        'enroll-confirm-btn',
        'enroll-status',
        'enroll-error',
        'enroll-short-pin-warning',
        'enroll-done',
        'reset-view',
        'reset-secret-new',
        'reset-secret-confirm',
        'reset-confirm-btn',
        'reset-status',
        'reset-error',
        'unavailable-view',
      ],
    ],
    [
      'popup.html',
      [
        'unlock-password',
        'unlock-btn',
        'unlock-error',
        'unlock-passkey-btn',
        'unlock-use-secret-btn',
        'unlock-secret-form',
        'passkey-offer',
        'passkey-offer-setup-btn',
        'passkey-offer-dismiss-btn',
      ],
    ],
    [
      'options.html',
      [
        'passkey-unlock-card',
        'passkey-unlock-list',
        'passkey-unlock-add-btn',
        'passkey-unlock-open-btn',
        'passkey-unlock-reset-link',
        'passkey-unlock-error',
        'passkey-unlock-remove-form',
        'passkey-unlock-remove-secret',
        'passkey-unlock-remove-confirm-btn',
        'passkey-unlock-remove-cancel-btn',
        'change-pw-keeps-key-note',
        'remove-pw-btn',
      ],
    ],
  ];

  it.each(ids)('%s has each of them once', (name, expected) => {
    const doc = page(name);
    for (const id of expected) {
      expect([id, doc.querySelectorAll(`[id="${id}"]`).length]).toEqual([id, 1]);
    }
  });

  it('builds the passkey rows in Options with the agreed classes', () => {
    const source = read('src/ui/options.ts');
    for (const name of [
      'unlock-passkey-row',
      'unlock-passkey-name',
      'unlock-passkey-rename-btn',
      'unlock-passkey-remove-btn',
    ]) {
      expect(source).toContain(`'${name}'`);
    }
    expect(source).toContain('row.dataset.credentialId = passkey.credentialId');
  });

  it('hides every status and error with the hidden attribute until it has text', () => {
    const doc = page('unlock.html');
    for (const id of [
      'unlock-status',
      'unlock-error',
      'enroll-status',
      'enroll-error',
      'reset-status',
      'reset-error',
    ]) {
      const el = doc.getElementById(id) as HTMLElement;
      expect([id, el.hasAttribute('hidden'), el.textContent]).toEqual([id, true, '']);
    }
    for (const id of ['unlock-error', 'enroll-error', 'reset-error']) {
      expect(doc.getElementById(id)?.getAttribute('role')).toBe('alert');
    }
    for (const id of ['unlock-status', 'enroll-status', 'reset-status']) {
      expect(doc.getElementById(id)?.getAttribute('aria-live')).toBe('polite');
    }
    // The views, and the passkey entry points on the other pages, start hidden.
    for (const id of ['unlock-view', 'enroll-view', 'reset-view', 'unavailable-view']) {
      expect(doc.getElementById(id)?.hasAttribute('hidden')).toBe(true);
    }
  });

  // Firefox cannot use the extension origin as a relying party: there the
  // background reports passkey unlock as unsupported and nothing is revealed.
  it('keeps every passkey entry point hidden until the background says it is supported', () => {
    const popup = page('popup.html');
    for (const id of ['unlock-passkey-btn', 'unlock-use-secret-btn', 'passkey-offer']) {
      expect([id, popup.getElementById(id)?.hasAttribute('hidden')]).toEqual([id, true]);
    }
    expect(popup.getElementById('setup-passkey-note')?.hasAttribute('hidden')).toBe(true);
    const options = page('options.html');
    for (const id of ['passkey-unlock-card', 'change-pw-keeps-key-note']) {
      expect([id, options.getElementById(id)?.hasAttribute('hidden')]).toEqual([id, true]);
    }
    expect(read('src/ui/popup.ts')).toMatch(/passkeyUnlock\?\.supported === true/);
    expect(read('src/ui/options.ts')).toContain('methods.supported !== true');
  });

  it('labels every field on the unlock page', () => {
    const doc = page('unlock.html');
    const inputs = Array.from(doc.querySelectorAll('input'));
    expect(inputs.length).toBeGreaterThan(0);
    // The lone PIN field of the lock screen is named by its placeholder, as
    // in the popup, and the page gives it the same accessible name.
    const byPlaceholder = ['fallback-secret'];
    for (const input of inputs) {
      const labels = doc.querySelectorAll(`label[for="${input.id}"]`).length;
      expect([input.id, labels]).toEqual([input.id, byPlaceholder.includes(input.id) ? 0 : 1]);
    }
    expect(doc.getElementById('fallback-secret')?.getAttribute('data-i18n-placeholder')).toBe(
      'unlockSecretLabel'
    );
    expect(read('src/ui/unlock.ts')).toContain(
      "el('fallback-secret').setAttribute('aria-label', t('unlockSecretLabel'))"
    );
  });
});

describe('what the screens say, and where', () => {
  const unlockPage = read('src/ui/unlock.ts');

  it('puts every error of the unlock page under the control it is about', () => {
    // One error element per view, moved to its field or button.
    expect(unlockPage).not.toMatch(/setText\(\s*'(unlock|enroll|reset)-error',\s*(?!'')\S/);
    const placed = [
      ...unlockPage.matchAll(/showError\(\s*'([a-z]+-error)',[\s\S]*?\n?\s*'([a-z-]+)'\s*\)/g),
    ].map((match) => `${match[1]} under ${match[2]}`);
    expect(placed).toEqual(
      expect.arrayContaining([
        'unlock-error under passkey-unlock-btn',
        'unlock-error under fallback-secret',
        'enroll-error under enroll-secret',
        'enroll-error under enroll-name',
        'reset-error under reset-secret-new',
        'reset-error under reset-secret-confirm',
        'reset-error under reset-confirm-btn',
      ])
    );
    expect(unlockPage).toContain("secretRefused ? 'enroll-secret' : 'enroll-create-btn'");
    // Every view keeps its error and status inside its form.
    const doc = page('unlock.html');
    for (const view of ['enroll', 'reset']) {
      expect(doc.getElementById(`${view}-error`)?.closest('form')?.id).toBe(`${view}-form`);
      expect(doc.getElementById(`${view}-status`)?.closest('form')?.id).toBe(`${view}-form`);
    }
  });

  it('gives the short-PIN advice once on the enrollment screen', () => {
    expect(unlockPage).toContain("el('enroll-short-pin-warning').hidden = !short;");
    expect(unlockPage).toContain("el('enroll-disclosure').hidden = short || !!pending;");
    // Never for a secret the vault refused, nor once the secret field is gone.
    expect(unlockPage).toMatch(/const short =\s*!pending && !secretRefused &&/);
    expect(unlockPage).toContain('secretRefused = error instanceof WrongSecret;');
  });

  it('ends each state of the unlock page with a heading for it and a way on', () => {
    const doc = page('unlock.html');
    for (const id of ['unlock-close-btn', 'enroll-close-btn', 'reset-close-btn']) {
      expect(doc.getElementById(id)?.querySelector('[data-i18n="unlockCloseTab"]')).not.toBeNull();
    }
    expect(doc.getElementById('unavailable-title')).not.toBeNull();
    expect(doc.getElementById('unavailable-action-btn')).not.toBeNull();
    expect(unlockPage).toContain("t('unlockEnrollDoneHeading')");
    expect(unlockPage).toContain("wasReset ? t('unlockResetDone') : t('unlockResetHeading')");
    expect(unlockPage).toContain("unlocked ? t('unlockUnlocked') : t('unlockHeading')");
    expect(unlockPage).toContain("el('enroll-help').hidden = enrolled;");
    expect(unlockPage).toContain("el('reset-help').hidden = wasReset;");
    // No lock set: the way on is the settings page that sets one.
    expect(unlockPage).toContain("showUnavailable(t('optionsPasskeySetSecretFirst'), 'settings')");
    expect(unlockPage).toContain("chrome.runtime.getURL('options.html#security')");
    expect(read('src/ui/options.ts')).toContain('openSectionFromHash');
    // Locked: the page unlocks right there, then shows what it was opened for.
    expect(unlockPage).toContain('renderUnlock(hasPasskey, mode)');
    // It says what it leads to, and a forgotten PIN is not asked for again.
    expect(unlockPage).toContain("t('unlockNeedsUnlockedEnroll')");
    expect(unlockPage).toContain("t('unlockNeedsUnlockedReset')");
    expect(unlockPage).toContain("const passkeyOnly = step === 'reset-secret';");
    expect(unlockPage).toContain(
      'toggle.hidden = unlocked || !hasPasskey || fallbackOpen || passkeyOnly;'
    );
    expect(unlockPage).toContain('closeBtn.hidden = !unlocked && !passkeyOnly;');
    expect(unlockPage).toContain("if (mode === 'unlock' && loadedMode === 'unlock')");
  });

  it('does not repeat the two unlock buttons in a line above them', () => {
    expect(translations.en.unlockHelp).toBeUndefined();
    expect(read('src/ui/popup.ts')).toContain('helpEl.hidden = hasPasskey;');
    expect(unlockPage).toContain("el('unlock-help').hidden = unlocked || (hasPasskey && !step);");
    // The popup keeps its heading off the first button without the line.
    expect(read('src/ui/popup.ts')).toContain(
      "lockScreen.classList.toggle('auth-no-hint', hasPasskey);"
    );
  });

  it('suggests another unlock method only where one is on offer', () => {
    expect(read('src/ui/popup.ts')).toMatch(
      /hasPasskey\s*\?\s*t\('popupVaultDamaged'\)\s*:\s*t\('popupVaultDamagedNoPasskey'\)/
    );
    expect(unlockPage).toMatch(
      /response\.code === 'VAULT_DAMAGED' && noPasskey\s*\?\s*t\('popupVaultDamagedNoPasskey'\)/
    );
    expect(translations.en.popupVaultDamagedNoPasskey).not.toMatch(/other unlock method/);
  });

  it('shows the popup offer only once the backup warning is gone, as one row', () => {
    const popup = read('src/ui/popup.ts');
    expect(popup).toContain('dismissed[VAULT_WARNING_DISMISSED_KEY] === true &&');
    expect(popup).toMatch(/async function dismissVaultWarning[\s\S]*?void initPasskeyOffer\(\);/);
    const offer = page('popup.html').getElementById('passkey-offer') as HTMLElement;
    expect(offer.querySelectorAll('button')).toHaveLength(2);
    expect(offer.querySelector('#passkey-offer-dismiss-btn')?.getAttribute('data-i18n-title')).toBe(
      'popupPasskeyOfferDismiss'
    );
  });

  it('keeps the Options card to what applies', () => {
    const options = read('src/ui/options.ts');
    // No card while no lock is set; the disclosure only with a passkey listed.
    expect(options).toContain('methods.supported !== true || methods.isSetup !== true');
    expect(options).toContain(
      "document.getElementById('passkey-unlock-disclosure')!.hidden = passkeys.length === 0;"
    );
    // The way out of a forgotten PIN sits in the PIN card, under its field.
    const doc = page('options.html');
    const link = doc.getElementById('passkey-unlock-reset-link') as HTMLElement;
    expect(link.closest('#master-pw-change')).not.toBeNull();
    expect(link.closest('#passkey-unlock-card')).toBeNull();
    expect(link.previousElementSibling?.id).toBe('change-pw-current');
    expect(link.hasAttribute('hidden')).toBe(true);
    expect(link.getAttribute('href')).toBe('unlock.html#reset-secret');
  });

  it('says what happens to a damaged passkey entry', () => {
    for (const key of ['optionsPasskeyDamaged_one', 'optionsPasskeyDamaged_other']) {
      expect(translations.en[key]).toMatch(/cleared the next time you add, rename or remove/);
      expect(translations.en[key]).toMatch(/add it again/);
    }
  });

  it('words turning off the lock as that, not as removing the PIN', () => {
    expect(translations.en.optionsRemoveNeedsCurrent).toMatch(/to turn off the vault lock\.$/);
    expect(translations.en.optionsRemoveConfirm).toMatch(/^Turn off the vault lock\?/);
    expect(missingTranslations(['optionsRemoveNeedsCurrent', 'optionsRemoveConfirm'])).toEqual([]);
  });

  it('uses sentence case in the Security section', () => {
    expect(translations.en.optionsLockNow).toBe('Lock now');
    expect(translations.en.optionsAutoLockTimeout).toBe('Auto-lock timeout');
    expect(translations.en.optionsNotSet).toBe('Not set');
    const security = page('options.html').getElementById('section-security') as HTMLElement;
    const titleCase = Array.from(security.querySelectorAll('h2, h3, button, .info-label'))
      .map((el) => (el.textContent ?? '').trim().replace(/\s+/g, ' '))
      .filter((text) => /^[A-Z][a-z-]+( [A-Z][a-z]+)+$/.test(text));
    expect(titleCase).toEqual([]);
    expect(read('src/ui/options.css')).toMatch(
      /\.card-row > \.info-label \{[^}]*text-transform: none;/
    );
  });
});

describe('what is checked before a passkey prompt opens', () => {
  /** The source of one top-level function of the unlock page. */
  function pageFunction(name: string): string {
    const source = read('src/ui/unlock.ts');
    const start = source.indexOf(`\nfunction ${name}(`);
    expect(start).toBeGreaterThan(-1);
    const end = source.indexOf('\n}\n', start);
    return source.slice(start, end);
  }

  // A passkey created for a vault that then refuses it stays at the provider.
  it('asks whether an upgrade backup is owed before creating a passkey', () => {
    const body = pageFunction('createPasskey');
    const check = body.indexOf('fresh.backupRequired');
    expect(check).toBeGreaterThan(-1);
    expect(check).toBeLessThan(body.indexOf('createUnlockPasskey('));
    expect(check).toBeLessThan(body.indexOf("send('VERIFY_MASTER_PASSWORD'"));
    expect(read('src/ui/unlock.ts')).toContain('backupRequired: response.backupRequired === true');
  });

  it('asks the same before a passkey sets a new PIN', () => {
    const body = pageFunction('resetSecret');
    const check = body.indexOf('fresh.backupRequired');
    expect(check).toBeGreaterThan(-1);
    expect(check).toBeLessThan(body.indexOf('readUnlockPrf('));
  });

  it('says a lock found before the prompt is a lock, not one during the prompt', () => {
    for (const name of ['createPasskey', 'resetSecret']) {
      const body = pageFunction(name);
      expect(body).toContain("if (!fresh.isUnlocked) throw new Shown(t('unlockNeedsUnlocked'))");
      expect(body).not.toContain("codeMessage('VAULT_LOCKED')");
    }
  });

  it('does not offer a passkey in the popup or Options while the backup is owed', () => {
    expect(read('src/ui/popup.ts')).toMatch(/backup\?\.required !== true/);
    expect(read('src/ui/options.ts')).toMatch(/addBtn\.hidden = .*backupRequired/);
  });
});

describe('the codes each screen has words for', () => {
  const cases = (source: string) =>
    [...source.matchAll(/case '([A-Z_]+)':\s*return t\('([A-Za-z]+)'/g)].map(
      (match) => `${match[1]} -> ${match[2]}`
    );

  it('explains damage and an owed backup in Options', () => {
    const source = read('src/ui/options.ts');
    const body = source.slice(
      source.indexOf('function passkeyUnlockFailure('),
      source.indexOf('function openUnlockPage(')
    );
    expect(cases(body)).toEqual(
      expect.arrayContaining([
        'VAULT_DAMAGED -> popupVaultDamaged',
        'UPGRADE_BACKUP_REQUIRED -> unlockErrBackupRequired',
      ])
    );
  });

  it('explains an owed backup and an unconfirmed format upgrade on the unlock page', () => {
    const source = read('src/ui/unlock.ts');
    expect(cases(source)).toEqual(
      expect.arrayContaining([
        'UPGRADE_BACKUP_REQUIRED -> unlockErrBackupRequired',
        'VAULT_WRITE_UNVERIFIED -> popupVaultWriteUnverified',
      ])
    );
    // The PIN form reports it instead of "wrong PIN".
    expect(source).toMatch(/response\.code === 'VAULT_WRITE_UNVERIFIED'\s*\?\s*codeMessage/);
  });

  it('explains an unconfirmed format upgrade on the popup lock screen', () => {
    expect(read('src/ui/popup.ts')).toMatch(
      /response\.code === 'VAULT_WRITE_UNVERIFIED'\s*\?\s*t\('popupVaultWriteUnverified'\)/
    );
    expect(missingTranslations(['popupVaultWriteUnverified', 'unlockErrBackupRequired'])).toEqual(
      []
    );
  });
});

describe('the words on these screens', () => {
  it('has every string of the unlock page in all seven languages', () => {
    const source = read('src/ui/unlock.ts');
    const used = [...source.matchAll(/\bt\(\s*'([^']+)'/g)].map((match) => match[1]);
    // Every string the page shows goes through a literal key.
    expect(source).not.toMatch(/\bt\(\s*[^'\s]/);
    expect(used.length).toBeGreaterThan(20);

    expect(missingTranslations([...i18nKeys(page('unlock.html')), ...used])).toEqual([]);
  });

  it('has the passkey unlock strings of the popup and Options in all seven languages', () => {
    const popup = page('popup.html');
    const options = page('options.html');
    const scoped = [
      popup.getElementById('unlock-passkey-btn'),
      popup.getElementById('unlock-use-secret-btn'),
      popup.getElementById('setup-passkey-note'),
      popup.getElementById('passkey-offer'),
      options.getElementById('passkey-unlock-card'),
      options.getElementById('change-pw-keeps-key-note')?.parentElement,
    ];
    const inMarkup = scoped.flatMap((el) => {
      expect(el).toBeTruthy();
      const self = (el as HTMLElement).dataset.i18n;
      return [...(self ? [self] : []), ...i18nKeys(el as HTMLElement)];
    });
    // Keys on the secret forms that predate this feature are not all translated.
    const added = inMarkup.filter(
      (key) =>
        /^(popupPasskey|popupUnlockWithPasskey|popupUsePinInstead|popupSetupPasskeyLater|optionsPasskey|optionsTurnOffLock|optionsChangeKeepsKeyNote|unlock)/.test(
          key
        ) || ['commonCancel', 'popupUnlock', 'vaultSecretHint'].includes(key)
    );
    expect(added).toEqual(
      expect.arrayContaining([
        'popupUnlockWithPasskey',
        'popupUsePinInstead',
        'popupSetupPasskeyLater',
        'popupPasskeyOfferTitle',
        'popupPasskeyOfferSetup',
        'popupPasskeyOfferDismiss',
        'optionsPasskeyUnlock',
        'optionsPasskeyAdd',
        'optionsPasskeyResetLink',
        'optionsPasskeyRemoveConfirm',
        'optionsTurnOffLock',
        'optionsChangeKeepsKeyNote',
        'unlockFallbackDisclosure',
      ])
    );

    const inScripts = ['src/ui/popup.ts', 'src/ui/options.ts'].flatMap((file) =>
      [
        ...read(file).matchAll(
          /'((?:popupVaultDamaged|popupWrongPassword|unlock[A-Z]|optionsPasskey|optionsRemoveConfirmWithPasskeys)\w*)'/g
        ),
      ].map((match) => match[1])
    );
    expect(inScripts).toEqual(
      expect.arrayContaining([
        'popupVaultDamaged',
        'popupVaultDamagedNoPasskey',
        'optionsPasskeyRemoveNote',
      ])
    );
    const plurals = ['optionsRemoveConfirmWithPasskeys', 'optionsPasskeyDamaged'];
    const keys = [...added, ...inScripts]
      .filter((key) => !plurals.includes(key))
      .concat(plurals.flatMap((key) => [`${key}_one`, `${key}_other`]));

    expect(missingTranslations(keys)).toEqual([]);
  });

  it('keeps the placeholders of each string in every language', () => {
    const placeholders = (text: string) => (text.match(/\{\w+\}/g) ?? []).sort();
    const keys = Object.keys(translations.en).filter((key) =>
      /^(unlock|optionsPasskey|optionsRemoveConfirmWithPasskeys|popupPasskeyOffer)/.test(key)
    );
    expect(keys.length).toBeGreaterThan(50);
    for (const key of keys) {
      for (const language of LANGUAGES) {
        expect([language, key, placeholders(translations[language][key] ?? '')]).toEqual([
          language,
          key,
          placeholders(translations.en[key]),
        ]);
      }
    }
  });

  it('says on the change form that a passkey keeps the vault from being re-encrypted', () => {
    const note = page('options.html').getElementById('change-pw-keeps-key-note') as HTMLElement;
    expect(note.closest('#master-pw-change')).not.toBeNull();
    expect(note.dataset.i18n).toBe('optionsChangeKeepsKeyNote');
    expect(translations.en.optionsChangeKeepsKeyNote).toMatch(/does not re-encrypt the vault/);
    expect(translations.en.optionsChangeKeepsKeyNote).toMatch(
      /remove the passkeys, change the PIN or passphrase, then add them again/
    );
  });

  it('asks before turning off the lock, counting the passkeys that stop working', () => {
    const source = read('src/ui/options.ts');
    expect(source).toContain("formatCount('optionsRemoveConfirmWithPasskeys', enrolled)");
    expect(source).toContain("t('optionsRemoveConfirm')");
    for (const key of [
      'optionsRemoveConfirmWithPasskeys_one',
      'optionsRemoveConfirmWithPasskeys_other',
    ]) {
      const text = translations.en[key];
      expect(text).toMatch(/^Turn off the vault lock\?/);
      expect(text).toMatch(/stored unencrypted/);
      expect(text).toContain('{count}');
      expect(text).toMatch(/stop working/);
      expect(text).toMatch(/stay at your passkey provider/);
    }
    const button = page('options.html').getElementById('remove-pw-btn') as HTMLElement;
    expect(button.querySelector('[data-i18n]')?.getAttribute('data-i18n')).toBe(
      'optionsTurnOffLock'
    );
  });

  // The product has no all-caps labels.
  it('adds no uppercase styling', () => {
    for (const file of ['src/ui/popup.css', 'src/ui/options.css']) {
      const css = read(file);
      const added = css.slice(css.indexOf('/* ---------- Passkey unlock ---------- */'));
      expect(added.length).toBeGreaterThan(100);
      expect(added).not.toMatch(/text-transform:\s*(?!none)\S/);
    }
    for (const key of Object.keys(translations.en).filter((k) =>
      /^(unlock|optionsPasskey)/.test(k)
    )) {
      const words = translations.en[key].split(/\s+/).filter((word) => /^[A-Z]{4,}$/.test(word));
      expect([key, words]).toEqual([key, []]);
    }
  });
});
