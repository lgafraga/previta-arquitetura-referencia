// Fluxo completo com dados sintéticos: guarda, prova, consentimento,
// revogação e eliminação. Mostra, no fim, tudo o que iria para a cadeia.
import { randomBytes } from 'node:crypto';
import { pseudonymize } from '../src/pseudonym.js';
import { Vault } from '../src/vault.js';
import { MerkleTree, verifyProof } from '../src/merkle.js';
import { ConsentLedger, KeyBroker } from '../src/consent.js';
import { batchMessage, consentMessage } from '../src/anchor.js';

const pepper = randomBytes(32); // em produção: chave do controlador, num KMS
const vault = new Vault();
const ledger = new ConsentLedger();
const broker = new KeyBroker({ vault, ledger });

// Paciente e médico fictícios.
const patient = pseudonymize('000.000.001-91', pepper);
const doctor = pseudonymize('crm-ba-00000', pepper, 'destinatario');

const documents = {
  'obs-psa-1': { resourceType: 'Observation', status: 'final', code: { text: 'PSA total' }, valueQuantity: { value: 1.2, unit: 'ng/mL' } },
  'proc-1': { resourceType: 'Procedure', status: 'completed', code: { text: 'Procedimento sintético' } },
  'cond-1': { resourceType: 'Condition', clinicalStatus: { text: 'active' }, code: { text: 'Condição sintética' } },
};

const commitments = Object.entries(documents).map(([id, doc]) => vault.put(id, JSON.stringify(doc)));
const tree = new MerkleTree(commitments.map((c) => c.commitment));
const onChain = [batchMessage({ root: tree.root, count: tree.size, batchId: 'lote-demo-0001' })];
console.log(`1. ${tree.size} documentos FHIR cifrados na instituição; raiz do lote ${tree.root.slice(0, 16)}…`);

const proof = tree.proof(0);
console.log(`2. Prova de inclusão do PSA: ${proof.length} hashes, válida = ${verifyProof(commitments[0].commitment, proof, tree.root)}`);

const { commitment } = commitments[0];
const grant = ledger.grant({ patient, grantee: doctor, commitment, purpose: 'segunda-opiniao', expiresAt: Date.now() + 86_400_000 });
broker.release({ docId: 'obs-psa-1', commitment, grantee: doctor });
console.log('3. Paciente concedeu acesso ao PSA para segunda opinião; chave liberada ao médico e uso registrado');

ledger.revoke({ grantId: grant.hash, patient, at: Date.now() + 1 });
try {
  broker.release({ docId: 'obs-psa-1', commitment, grantee: doctor, at: Date.now() + 2 });
} catch (err) {
  console.log(`4. Paciente revogou; nova tentativa recusada: "${err.message}"`);
}

vault.shred('proc-1');
console.log('5. Eliminação do procedimento: chave e sal destruídos, texto cifrado apagado; a raiz ancorada segue íntegra');

onChain.push(...ledger.events.map(consentMessage));
console.log(`\nO que iria para o HCS (${onChain.length} mensagens, nenhuma com dado pessoal ou clínico):`);
for (const m of onChain) console.log(' ', m.length > 150 ? `${m.slice(0, 150)}…` : m);
