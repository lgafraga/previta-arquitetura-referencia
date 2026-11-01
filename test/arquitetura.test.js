import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { pseudonymize } from '../src/pseudonym.js';
import { Vault, decrypt } from '../src/vault.js';
import { MerkleTree, verifyProof } from '../src/merkle.js';
import { ConsentLedger, KeyBroker } from '../src/consent.js';
import { batchMessage, consentMessage } from '../src/anchor.js';

const KEY = randomBytes(32);
const HOUR = 3_600_000;
// CPF fictício, gerado só para teste.
const CPF = '123.456.789-09';

test('pseudônimo com chave não é o SHA-256 do CPF e não depende da pontuação', () => {
  const p = pseudonymize(CPF, KEY);
  assert.equal(p, pseudonymize('12345678909', KEY));
  assert.notEqual(p, createHash('sha256').update('12345678909').digest('hex'));
  assert.notEqual(p, pseudonymize(CPF, randomBytes(32)), 'sem a chave, não se recalcula');
  assert.notEqual(p, pseudonymize(CPF, KEY, 'destinatario'), 'domínios separados');
  assert.throws(() => pseudonymize(CPF, Buffer.alloc(16)), /32 bytes/);
});

test('documento cifrado só abre com a chave e o compromisso não é hash do conteúdo', () => {
  const vault = new Vault();
  const doc = JSON.stringify({ resourceType: 'Observation', status: 'final' });
  const { commitment } = vault.put('obs-1', doc);
  assert.equal(decrypt('obs-1', vault.getCiphertext('obs-1'), vault.releaseKey('obs-1')).toString(), doc);
  assert.notEqual(commitment, createHash('sha256').update(doc).digest('hex'));
  assert.notEqual(commitment, new Vault().put('obs-1', doc).commitment, 'sal diferente por registro');
  assert.throws(() => decrypt('obs-1', vault.getCiphertext('obs-1'), randomBytes(32)));
});

test('prova de Merkle confirma um registro sem expor os outros e falha se adulterado', () => {
  for (const n of [1, 2, 3, 5, 8, 13]) {
    const commitments = Array.from({ length: n }, () => randomBytes(32).toString('hex'));
    const tree = new MerkleTree(commitments);
    commitments.forEach((c, i) => assert.ok(verifyProof(c, tree.proof(i), tree.root), `n=${n} i=${i}`));
    const forged = randomBytes(32).toString('hex');
    assert.equal(verifyProof(forged, tree.proof(0), tree.root), false);
    if (n > 1) assert.equal(verifyProof(commitments[0], tree.proof(1), tree.root), false);
  }
});

test('lote com o último registro repetido não produz a mesma raiz', () => {
  const [a, b, c] = Array.from({ length: 3 }, () => randomBytes(32).toString('hex'));
  assert.notEqual(new MerkleTree([a, b, c]).root, new MerkleTree([a, b, c, c]).root);
});

test('chave só sai com consentimento ativo; revogação e prazo encerram a liberação', () => {
  const vault = new Vault();
  const ledger = new ConsentLedger();
  const broker = new KeyBroker({ vault, ledger });
  const patient = pseudonymize(CPF, KEY);
  const grantee = pseudonymize('medico@exemplo.org', KEY, 'destinatario');
  const { commitment } = vault.put('obs-1', 'conteúdo clínico sintético');
  const t0 = 1_000_000;

  assert.throws(() => broker.release({ docId: 'obs-1', commitment, grantee, at: t0 }), /Sem consentimento/);
  const grant = ledger.grant({ patient, grantee, commitment, purpose: 'assistencia', expiresAt: t0 + 24 * HOUR, at: t0 });
  assert.ok(broker.release({ docId: 'obs-1', commitment, grantee, at: t0 + HOUR }));
  assert.throws(() => broker.release({ docId: 'obs-1', commitment, grantee: patient, at: t0 + HOUR }), /Sem consentimento/);

  assert.throws(() => ledger.revoke({ grantId: grant.hash, patient: grantee, at: t0 + 2 * HOUR }), /titular/);
  ledger.revoke({ grantId: grant.hash, patient, at: t0 + 2 * HOUR });
  assert.ok(broker.release({ docId: 'obs-1', commitment, grantee, at: t0 + HOUR }), 'revogação não retroage');
  assert.throws(() => broker.release({ docId: 'obs-1', commitment, grantee, at: t0 + 3 * HOUR }), /Sem consentimento/);

  const g2 = ledger.grant({ patient, grantee, commitment, purpose: 'assistencia', expiresAt: t0 + 5 * HOUR, at: t0 + 4 * HOUR });
  assert.ok(g2);
  assert.throws(() => broker.release({ docId: 'obs-1', commitment, grantee, at: t0 + 6 * HOUR }), /Sem consentimento/);

  assert.deepEqual(ledger.events.map((e) => e.type), ['grant', 'use', 'revoke', 'use', 'grant']);
  assert.ok(ledger.verifyChain());
});

test('alterar um evento antigo quebra a cadeia de consentimento', () => {
  const ledger = new ConsentLedger();
  const id = (s) => pseudonymize(s, KEY);
  const grant = ledger.grant({ patient: id('a'), grantee: id('b'), commitment: id('c'), purpose: 'assistencia', expiresAt: 2, at: 1 });
  ledger.revoke({ grantId: grant.hash, patient: id('a'), at: 1 });
  assert.ok(ledger.verifyChain());
  ledger.events[0] = { ...ledger.events[0], expiresAt: 999 };
  assert.equal(ledger.verifyChain(), false);
});

test('consentimento recusa identificador em claro e finalidade fora da lista', () => {
  const ledger = new ConsentLedger();
  const p = pseudonymize(CPF, KEY);
  assert.throws(() => ledger.grant({ patient: CPF, grantee: p, commitment: p, purpose: 'assistencia', expiresAt: 2, at: 1 }), /pseudônimo/);
  assert.throws(() => ledger.grant({ patient: p, grantee: p, commitment: p, purpose: 'venda', expiresAt: 2, at: 1 }), /Finalidade/);
});

test('eliminação: destruída a chave, o documento não volta e a folha ancorada não identifica nada', () => {
  const vault = new Vault();
  const doc = 'laudo sintético';
  const { commitment } = vault.put('laudo-1', doc);
  const tree = new MerkleTree([commitment, randomBytes(32).toString('hex')]);
  const proof = tree.proof(0);

  assert.ok(vault.shred('laudo-1'));
  assert.throws(() => vault.releaseKey('laudo-1'), /destruída/);
  assert.throws(() => vault.getCiphertext('laudo-1'), /eliminado/);
  // A raiz já ancorada continua íntegra, mas sem o sal ninguém liga a folha ao conteúdo.
  assert.ok(verifyProof(commitment, proof, tree.root));
  assert.notEqual(commitment, createHash('sha256').update(doc).digest('hex'));
});

test('mensagens para a cadeia só levam campos permitidos e nenhum dado pessoal', () => {
  const ledger = new ConsentLedger();
  const p = pseudonymize(CPF, KEY);
  const event = ledger.grant({ patient: p, grantee: p, commitment: p, purpose: 'assistencia', expiresAt: 2, at: 1 });
  const messages = [batchMessage({ root: p, count: 50, batchId: 'lote-0001', at: 1 }), consentMessage(event)];
  for (const m of messages) {
    assert.ok(!m.includes('123.456.789') && !m.includes('12345678909'));
    assert.ok(Buffer.byteLength(m) <= 1024);
  }
  assert.throws(() => batchMessage({ root: p, count: 1, batchId: CPF }), /dado pessoal/);
  assert.throws(() => consentMessage({ ...event, nome: 'Fulano' }), /não permitido/);
});
