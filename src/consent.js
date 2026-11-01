// Consentimento executado por código.
//
// O paciente concede acesso a um documento (pelo compromisso, nunca pelo
// conteúdo), a um destinatário, para uma finalidade e por um prazo. Cada
// concessão, uso e revogação é um evento encadeado por hash: alterar ou
// remover um evento antigo quebra a cadeia. Os eventos levam só pseudônimos e
// compromissos, por isso podem ser ancorados numa rede pública.
//
// A revogação não apaga a concessão: é um novo evento que, a partir do seu
// registro, impede a liberação da chave.
//
// O ConsentLedger faz em memória o papel do smart contract: as mesmas regras,
// sem depender de rede, para que possam ser testadas e auditadas.
import { createHash } from 'node:crypto';

const GENESIS = '0'.repeat(64);
const PSEUDONYM = /^[0-9a-f]{64}$/;
// Finalidade vem de uma lista fechada: texto livre poderia carregar dado pessoal
// para a cadeia.
export const PURPOSES = new Set(['assistencia', 'segunda-opiniao', 'auditoria-faturamento', 'pesquisa-anonimizada']);

export class ConsentLedger {
  constructor() {
    this.events = [];
  }

  #append(fields) {
    const prev = this.events.at(-1)?.hash ?? GENESIS;
    const event = { ...fields, seq: this.events.length, prev };
    event.hash = hashEvent(event);
    this.events.push(Object.freeze(event));
    return event;
  }

  grant({ patient, grantee, commitment, purpose, expiresAt, at = Date.now() }) {
    for (const [name, value] of Object.entries({ patient, grantee, commitment })) {
      if (!PSEUDONYM.test(value)) throw new Error(`${name} precisa ser pseudônimo ou compromisso (64 hex)`);
    }
    if (!PURPOSES.has(purpose)) throw new Error(`Finalidade fora da lista: ${purpose}`);
    if (!(expiresAt > at)) throw new Error('Prazo precisa ser posterior à concessão');
    return this.#append({ type: 'grant', patient, grantee, commitment, purpose, expiresAt, at });
  }

  revoke({ grantId, patient, at = Date.now() }) {
    const grant = this.events.find((e) => e.type === 'grant' && e.hash === grantId);
    if (!grant) throw new Error('Concessão inexistente');
    if (grant.patient !== patient) throw new Error('Só o titular revoga a própria concessão');
    return this.#append({ type: 'revoke', grantId, patient, at });
  }

  recordUse({ grantId, grantee, at = Date.now() }) {
    return this.#append({ type: 'use', grantId, grantee, at });
  }

  activeGrant({ grantee, commitment, at = Date.now() }) {
    const revoked = new Set(
      this.events.filter((e) => e.type === 'revoke' && e.at <= at).map((e) => e.grantId),
    );
    return this.events.find(
      (e) =>
        e.type === 'grant' &&
        e.grantee === grantee &&
        e.commitment === commitment &&
        e.at <= at &&
        at < e.expiresAt &&
        !revoked.has(e.hash),
    );
  }

  verifyChain() {
    let prev = GENESIS;
    return this.events.every((e) => {
      const ok = e.prev === prev && e.hash === hashEvent(e);
      prev = e.hash;
      return ok;
    });
  }
}

// Libera a chave de um documento só ao destinatário com concessão ativa, e
// registra o uso. Sem concessão, a chave não sai do cofre.
export class KeyBroker {
  constructor({ vault, ledger }) {
    this.vault = vault;
    this.ledger = ledger;
  }

  release({ docId, commitment, grantee, at = Date.now() }) {
    const grant = this.ledger.activeGrant({ grantee, commitment, at });
    if (!grant) throw new Error('Sem consentimento ativo para este destinatário e documento');
    this.ledger.recordUse({ grantId: grant.hash, grantee, at });
    return this.vault.releaseKey(docId);
  }
}

export function hashEvent(event) {
  const { hash, ...fields } = event;
  const canonical = JSON.stringify(Object.fromEntries(Object.entries(fields).sort(([a], [b]) => a.localeCompare(b))));
  return createHash('sha256').update(canonical).digest('hex');
}
