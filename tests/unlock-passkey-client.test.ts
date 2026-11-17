/**
 * The WebAuthn side of passkey unlock, against a fake CredentialsContainer:
 * exactly what is asked of the browser, and how each answer is read. The
 * real thing is exercised end to end in tests/e2e/passkey-unlock.test.cjs.
 */

import {
  confirmUnlockPasskey,
  createUnlockPasskey,
  readUnlockPrf,
  UnlockCeremonyError,
  type CeremonyFailure,
  type EnrolledRef,
} from '../src/ui/unlock-passkey-client';

type PrfResults = { enabled?: boolean; results?: { first?: unknown } } | undefined;

const bytes = (length: number, fill: number) => new Uint8Array(length).fill(fill);
const base64 = (value: Uint8Array) => Buffer.from(value).toString('base64');
const base64url = (value: Uint8Array) => Buffer.from(value).toString('base64url');
/** A BufferSource as plain numbers, whichever view or buffer it is. */
const plain = (value: unknown): number[] =>
  ArrayBuffer.isView(value)
    ? Array.from(new Uint8Array(value.buffer, value.byteOffset, value.byteLength))
    : Array.from(new Uint8Array(value as ArrayBuffer));

const RAW_ID = bytes(20, 7);
const CREDENTIAL_ID = base64url(RAW_ID);
const OUTPUT = bytes(32, 9);

function credential(rawId: Uint8Array, prf: PrfResults, transports?: unknown) {
  return {
    type: 'public-key',
    rawId: rawId.buffer.slice(rawId.byteOffset, rawId.byteOffset + rawId.byteLength),
    getClientExtensionResults: () => (prf === undefined ? {} : { prf }),
    response: { getTransports: () => transports },
  };
}

function fakeCredentials(answers: { create?: unknown; get?: unknown }) {
  const answer = (value: unknown) =>
    jest.fn(async () => {
      if (value instanceof Error) throw value;
      return value;
    });
  const container = { create: answer(answers.create), get: answer(answers.get) };
  return {
    container: container as unknown as CredentialsContainer,
    create: container.create,
    get: container.get,
    createOptions: () => (container.create.mock.calls[0] as any)[0].publicKey,
    getOptions: () => (container.get.mock.calls[0] as any)[0].publicKey,
  };
}

function domError(name: string): Error {
  return Object.assign(new Error(name), { name });
}

async function reasonOf(promise: Promise<unknown>): Promise<CeremonyFailure | 'resolved'> {
  try {
    await promise;
    return 'resolved';
  } catch (error) {
    expect(error).toBeInstanceOf(UnlockCeremonyError);
    return (error as UnlockCeremonyError).reason;
  }
}

const enrolled = (salt = bytes(32, 3)): EnrolledRef => ({
  credentialId: CREDENTIAL_ID,
  prfSalt: base64(salt),
  transports: ['internal'],
});

describe('creating an unlock passkey', () => {
  it('asks for a passkey at this origin, verified, with a PRF salt of its own', async () => {
    const other = bytes(16, 5);
    const fake = fakeCredentials({
      create: credential(RAW_ID, { enabled: true, results: { first: OUTPUT } }, ['internal']),
    });

    const created = await createUnlockPasskey(fake.container, {
      name: 'Laptop',
      excludeCredentialIds: [base64url(other)],
    });

    const options = fake.createOptions();
    // The relying party is the extension's origin: no rp.id.
    expect(options.rp).toEqual({ name: 'Passkey.bond' });
    expect(options.user.name).toBe('Passkey.bond vault unlock');
    expect(options.user.displayName).toBe('Laptop');
    expect(plain(options.user.id)).toHaveLength(16);
    expect(plain(options.challenge)).toHaveLength(32);
    expect(options.pubKeyCredParams).toEqual([
      { type: 'public-key', alg: -7 },
      { type: 'public-key', alg: -257 },
    ]);
    expect(options.authenticatorSelection).toEqual({
      userVerification: 'required',
      residentKey: 'discouraged',
    });
    expect(options.attestation).toBe('none');
    expect(options.excludeCredentials).toHaveLength(1);
    expect(options.excludeCredentials[0].type).toBe('public-key');
    expect(plain(options.excludeCredentials[0].id)).toEqual(Array.from(other));
    // The salt goes in eval at creation; evalByCredential is not legal there.
    expect(Object.keys(options.extensions)).toEqual(['prf']);
    expect(Object.keys(options.extensions.prf)).toEqual(['eval']);
    expect(plain(options.extensions.prf.eval.first)).toHaveLength(32);
    expect(Object.keys((fake.create.mock.calls[0] as any)[0])).toEqual(['publicKey']);

    expect(created.credentialId).toBe(CREDENTIAL_ID);
    expect(created.transports).toEqual(['internal']);
    expect(plain(created.createOutput)).toEqual(Array.from(OUTPUT));
    // What is stored as the salt is what the provider was given.
    expect(Array.from(Buffer.from(created.prfSalt, 'base64'))).toEqual(
      plain(options.extensions.prf.eval.first)
    );
  });

  it('uses a fresh user ID, salt and challenge each time', async () => {
    const answer = credential(RAW_ID, { enabled: true });
    const first = fakeCredentials({ create: answer });
    const second = fakeCredentials({ create: answer });
    const input = { name: 'Key', excludeCredentialIds: [] };

    const a = await createUnlockPasskey(first.container, input);
    const b = await createUnlockPasskey(second.container, input);

    expect(plain(first.createOptions().user.id)).not.toEqual(plain(second.createOptions().user.id));
    expect(plain(first.createOptions().challenge)).not.toEqual(
      plain(second.createOptions().challenge)
    );
    expect(a.prfSalt).not.toBe(b.prfSalt);
  });

  it('accepts a provider that enables PRF without returning a result yet', async () => {
    const fake = fakeCredentials({ create: credential(RAW_ID, { enabled: true }) });

    const created = await createUnlockPasskey(fake.container, {
      name: 'Key',
      excludeCredentialIds: [],
    });

    expect(created.createOutput).toBeNull();
    expect(created.transports).toEqual([]);
  });

  it.each<[string, PrfResults]>([
    ['no PRF extension result', undefined],
    ['PRF not enabled', { enabled: false }],
    ['an empty PRF result', {}],
    ['a result of the wrong length and not enabled', { results: { first: bytes(16, 1) } }],
  ])('stops with no-prf on %s, before any second prompt', async (_label, prf) => {
    const fake = fakeCredentials({ create: credential(RAW_ID, prf) });

    const reason = await reasonOf(
      createUnlockPasskey(fake.container, { name: 'Key', excludeCredentialIds: [] })
    );

    expect(reason).toBe('no-prf');
    expect(fake.get).not.toHaveBeenCalled();
  });

  it('keeps only transports the vault knows', async () => {
    const fake = fakeCredentials({
      create: credential(RAW_ID, { enabled: true }, ['usb', 'cable', 'nfc', 7]),
    });

    const created = await createUnlockPasskey(fake.container, {
      name: 'Key',
      excludeCredentialIds: [],
    });

    expect(created.transports).toEqual(['usb', 'nfc']);
  });

  it.each<[string, CeremonyFailure]>([
    ['NotAllowedError', 'cancelled'],
    ['AbortError', 'cancelled'],
    ['InvalidStateError', 'excluded'],
    ['SecurityError', 'unsupported'],
    ['NotSupportedError', 'unsupported'],
    ['UnknownError', 'failed'],
  ])('reports %s as %s', async (name, expected) => {
    const fake = fakeCredentials({ create: domError(name) });

    expect(
      await reasonOf(createUnlockPasskey(fake.container, { name: 'Key', excludeCredentialIds: [] }))
    ).toBe(expected);
  });

  it('reports a browser without WebAuthn as unsupported', async () => {
    const input = { name: 'Key', excludeCredentialIds: [] };

    expect(await reasonOf(createUnlockPasskey(undefined as never, input))).toBe('unsupported');
    expect(await reasonOf(createUnlockPasskey({} as CredentialsContainer, input))).toBe(
      'unsupported'
    );
    expect(await reasonOf(readUnlockPrf({} as CredentialsContainer, [enrolled()]))).toBe(
      'unsupported'
    );
  });

  it('fails when the browser returns no credential', async () => {
    const fake = fakeCredentials({ create: null });

    expect(
      await reasonOf(createUnlockPasskey(fake.container, { name: 'Key', excludeCredentialIds: [] }))
    ).toBe('failed');
  });
});

describe('reading the PRF output of an enrolled passkey', () => {
  it('sends an allow list, requires verification and gives each passkey its own salt', async () => {
    const otherId = bytes(32, 8);
    const otherSalt = bytes(32, 4);
    const salt = bytes(32, 3);
    const fake = fakeCredentials({
      get: credential(otherId, { results: { first: OUTPUT } }),
    });

    const result = await readUnlockPrf(fake.container, [
      enrolled(salt),
      { credentialId: base64url(otherId), prfSalt: base64(otherSalt) },
    ]);

    const options = fake.getOptions();
    // The relying party is the extension's origin: no rpId.
    expect(Object.keys(options).sort()).toEqual([
      'allowCredentials',
      'challenge',
      'extensions',
      'userVerification',
    ]);
    expect(plain(options.challenge)).toHaveLength(32);
    expect(options.userVerification).toBe('required');
    expect(options.allowCredentials).toHaveLength(2);
    expect(options.allowCredentials[0].type).toBe('public-key');
    expect(plain(options.allowCredentials[0].id)).toEqual(Array.from(RAW_ID));
    expect(options.allowCredentials[0].transports).toEqual(['internal']);
    expect(plain(options.allowCredentials[1].id)).toEqual(Array.from(otherId));
    expect('transports' in options.allowCredentials[1]).toBe(false);
    expect(Object.keys(options.extensions.prf)).toEqual(['evalByCredential']);
    const byCredential = options.extensions.prf.evalByCredential;
    expect(Object.keys(byCredential)).toEqual([CREDENTIAL_ID, base64url(otherId)]);
    expect(plain(byCredential[CREDENTIAL_ID].first)).toEqual(Array.from(salt));
    expect(plain(byCredential[base64url(otherId)].first)).toEqual(Array.from(otherSalt));

    // The wrapper is chosen by the credential that answered.
    expect(result.credentialId).toBe(base64url(otherId));
    expect(plain(result.prfOutput)).toEqual(Array.from(OUTPUT));
  });

  it('returns a copy the caller can wipe', async () => {
    const answer = bytes(32, 9);
    const fake = fakeCredentials({ get: credential(RAW_ID, { results: { first: answer } }) });

    const { prfOutput } = await readUnlockPrf(fake.container, [enrolled()]);
    prfOutput.fill(0);

    expect(Array.from(answer)).toEqual(Array.from(OUTPUT));
  });

  it.each<[string, PrfResults]>([
    ['no PRF extension result', undefined],
    ['no results', { enabled: true }],
    ['a 31-byte result', { results: { first: bytes(31, 9) } }],
    ['a 64-byte result', { results: { first: bytes(64, 9) } }],
    ['a result that is not bytes', { results: { first: 'c2VjcmV0' } }],
  ])('reports no-prf on %s', async (_label, prf) => {
    const fake = fakeCredentials({ get: credential(RAW_ID, prf) });

    expect(await reasonOf(readUnlockPrf(fake.container, [enrolled()]))).toBe('no-prf');
  });

  it('fails on a credential that is not in the allow list', async () => {
    const fake = fakeCredentials({
      get: credential(bytes(20, 1), { results: { first: OUTPUT } }),
    });

    expect(await reasonOf(readUnlockPrf(fake.container, [enrolled()]))).toBe('failed');
  });

  it('never prompts without an allow list', async () => {
    const fake = fakeCredentials({ get: credential(RAW_ID, { results: { first: OUTPUT } }) });

    expect(await reasonOf(readUnlockPrf(fake.container, []))).toBe('failed');
    expect(fake.get).not.toHaveBeenCalled();
  });

  it.each<[string, CeremonyFailure]>([
    ['NotAllowedError', 'cancelled'],
    ['AbortError', 'cancelled'],
    // Only creation can be refused for an excluded credential.
    ['InvalidStateError', 'failed'],
    ['SecurityError', 'unsupported'],
    ['UnknownError', 'failed'],
  ])('reports %s as %s', async (name, expected) => {
    const fake = fakeCredentials({ get: domError(name) });

    expect(await reasonOf(readUnlockPrf(fake.container, [enrolled()]))).toBe(expected);
  });
});

describe('confirming a new passkey before it is stored', () => {
  const created = (createOutput: Uint8Array | null) => ({
    credentialId: CREDENTIAL_ID,
    prfSalt: base64(bytes(32, 3)),
    transports: ['usb'],
    createOutput,
  });

  it('asks only the new passkey, with its salt', async () => {
    const fake = fakeCredentials({ get: credential(RAW_ID, { results: { first: OUTPUT } }) });

    await confirmUnlockPasskey(fake.container, created(null));

    const options = fake.getOptions();
    expect(options.allowCredentials).toHaveLength(1);
    expect(plain(options.allowCredentials[0].id)).toEqual(Array.from(RAW_ID));
    expect(options.allowCredentials[0].transports).toEqual(['usb']);
    expect(plain(options.extensions.prf.evalByCredential[CREDENTIAL_ID].first)).toEqual(
      Array.from(bytes(32, 3))
    );
  });

  it('returns the get-time output when creation returned none', async () => {
    const fake = fakeCredentials({ get: credential(RAW_ID, { results: { first: OUTPUT } }) });

    const output = await confirmUnlockPasskey(fake.container, created(null));

    expect(plain(output)).toEqual(Array.from(OUTPUT));
  });

  it('returns the output when it equals the one from creation', async () => {
    const fake = fakeCredentials({ get: credential(RAW_ID, { results: { first: OUTPUT } }) });

    const output = await confirmUnlockPasskey(fake.container, created(bytes(32, 9)));

    expect(plain(output)).toEqual(Array.from(OUTPUT));
  });

  it('refuses a passkey that answers differently the second time', async () => {
    const fake = fakeCredentials({ get: credential(RAW_ID, { results: { first: OUTPUT } }) });

    expect(await reasonOf(confirmUnlockPasskey(fake.container, created(bytes(32, 1))))).toBe(
      'prf-unstable'
    );
  });

  it('reports a passkey that returns nothing at get as no-prf', async () => {
    const fake = fakeCredentials({ get: credential(RAW_ID, { enabled: true }) });

    expect(await reasonOf(confirmUnlockPasskey(fake.container, created(null)))).toBe('no-prf');
  });

  it('reports a dismissed confirmation as cancelled', async () => {
    const fake = fakeCredentials({ get: domError('NotAllowedError') });

    expect(await reasonOf(confirmUnlockPasskey(fake.container, created(null)))).toBe('cancelled');
  });
});
