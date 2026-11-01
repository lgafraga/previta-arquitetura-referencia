// Árvore de Merkle com prova de inclusão.
//
// Milhares de compromissos viram uma única raiz, que é o que se ancora na rede.
// A prova de inclusão de uma folha tem log2(n) hashes e permite a um auditor
// confirmar que aquele registro estava no lote e não foi alterado, sem ver os
// demais registros (privacidade auditável, Resolução CVM 249, art. 3º, II).
//
// Prefixos distintos para folha (0x00) e nó interno (0x01), como na RFC 6962,
// impedem que um nó interno seja apresentado como folha. Com número ímpar de
// nós, o último sobe sem ser duplicado, o que evita que dois lotes diferentes
// produzam a mesma raiz.
import { createHash } from 'node:crypto';

const sha256 = (...parts) => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
};

export const hashLeaf = (commitmentHex) => sha256(Buffer.from([0x00]), Buffer.from(commitmentHex, 'hex'));
const hashNode = (left, right) => sha256(Buffer.from([0x01]), left, right);

export class MerkleTree {
  constructor(commitments) {
    if (!commitments.length) throw new Error('Lote vazio');
    this.levels = [commitments.map(hashLeaf)];
    while (this.levels.at(-1).length > 1) {
      const level = this.levels.at(-1);
      const next = [];
      for (let i = 0; i < level.length; i += 2) {
        next.push(i + 1 < level.length ? hashNode(level[i], level[i + 1]) : level[i]);
      }
      this.levels.push(next);
    }
  }

  get root() {
    return this.levels.at(-1)[0].toString('hex');
  }

  get size() {
    return this.levels[0].length;
  }

  proof(index) {
    if (index < 0 || index >= this.size) throw new Error(`Índice fora do lote: ${index}`);
    const path = [];
    for (const level of this.levels.slice(0, -1)) {
      const sibling = index % 2 === 0 ? index + 1 : index - 1;
      if (sibling < level.length) {
        path.push({ position: index % 2 === 0 ? 'right' : 'left', hash: level[sibling].toString('hex') });
      }
      index = Math.floor(index / 2);
    }
    return path;
  }
}

export function verifyProof(commitmentHex, proof, rootHex) {
  let acc = hashLeaf(commitmentHex);
  for (const { position, hash } of proof) {
    const sibling = Buffer.from(hash, 'hex');
    acc = position === 'right' ? hashNode(acc, sibling) : hashNode(sibling, acc);
  }
  return acc.toString('hex') === rootHex;
}
