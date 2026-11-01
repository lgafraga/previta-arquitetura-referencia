// Cofre de documentos fora da cadeia, na instituição que tem a guarda legal.
//
// Cada documento é cifrado com AES-256-GCM e uma chave própria (uma chave por
// documento). O compromisso que vai para a árvore de Merkle é um HMAC do
// conteúdo com um sal aleatório do registro: sem o sal, ninguém consegue testar
// se um conteúdo conhecido corresponde a uma folha da árvore.
//
// Eliminação (LGPD, art. 18, VI): `shred` destrói a chave e o sal e apaga o
// texto cifrado. A folha continua na árvore já ancorada, mas não reconstrói nem
// identifica o conteúdo.
import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto';

export class Vault {
  // Os dois Maps representam armazenamentos separados: em produção, o de chaves
  // seria um HSM ou KMS e o de documentos, o repositório da instituição.
  constructor({ keyStore = new Map(), blobStore = new Map() } = {}) {
    this.keyStore = keyStore;
    this.blobStore = blobStore;
  }

  put(docId, content) {
    if (this.blobStore.has(docId)) throw new Error(`Documento já existe: ${docId}`);
    const plaintext = Buffer.from(content);
    const key = randomBytes(32);
    const salt = randomBytes(32);
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(Buffer.from(docId));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    this.blobStore.set(docId, { iv, ciphertext, tag: cipher.getAuthTag() });
    this.keyStore.set(docId, { key, salt });
    return { docId, commitment: commitment(salt, plaintext) };
  }

  // Só o KeyBroker deve chamar: a liberação da chave depende do consentimento.
  releaseKey(docId) {
    const entry = this.keyStore.get(docId);
    if (!entry) throw new Error(`Chave inexistente ou destruída: ${docId}`);
    return entry.key;
  }

  getCiphertext(docId) {
    const blob = this.blobStore.get(docId);
    if (!blob) throw new Error(`Documento inexistente ou eliminado: ${docId}`);
    return blob;
  }

  shred(docId) {
    const existed = this.keyStore.delete(docId);
    this.blobStore.delete(docId);
    return existed;
  }
}

export function decrypt(docId, { iv, ciphertext, tag }, key) {
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(Buffer.from(docId));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export function commitment(salt, plaintext) {
  return createHmac('sha256', salt).update(plaintext).digest('hex');
}
