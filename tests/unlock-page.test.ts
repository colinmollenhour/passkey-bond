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
    for (const input of inputs) {
      expect([input.id, doc.querySelectorAll(`label[for="${input.id}"]`).length]).toEqual([
        input.id,
        1,
      ]);
    }
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
      expect.arrayContaining(['popupVaultDamaged', 'unlockHelp', 'optionsPasskeyRemoveNote'])
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
      expect(added).not.toMatch(/text-transform/);
    }
    for (const key of Object.keys(translations.en).filter((k) =>
      /^(unlock|optionsPasskey)/.test(k)
    )) {
      const words = translations.en[key].split(/\s+/).filter((word) => /^[A-Z]{4,}$/.test(word));
      expect([key, words]).toEqual([key, []]);
    }
  });
});
