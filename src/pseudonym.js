// Pseudonimização com hash com chave (HMAC-SHA256).
//
// Um hash simples de um dado de baixa entropia, como o CPF (cerca de 10^9
// combinações), é revertido por força bruta em minutos. Com HMAC, quem não tem
// a chave não consegue recalcular o pseudônimo, e a chave fica com o
// controlador, fora da rede. A tabela de reidentificação é o próprio cálculo:
// o controlador recalcula o HMAC do identificador quando a autoridade pede.
import { createHmac } from 'node:crypto';

const MIN_KEY_BYTES = 32;

export function normalizeIdentifier(identifier) {
  const value = String(identifier).trim();
  // CPF e CNS chegam com ou sem pontuação; o pseudônimo não pode depender disso.
  return /^[\d.\-\s/]+$/.test(value) ? value.replace(/\D/g, '') : value.toLowerCase();
}

// `context` separa domínios: o mesmo CPF gera pseudônimos diferentes para
// "paciente" e para "destinatario", e os dois não podem ser cruzados.
export function pseudonymize(identifier, key, context = 'paciente') {
  if (!Buffer.isBuffer(key) || key.length < MIN_KEY_BYTES) {
    throw new Error(`A chave de pseudonimização precisa ter pelo menos ${MIN_KEY_BYTES} bytes`);
  }
  return createHmac('sha256', key)
    .update(`previta:${context}:v1\0`)
    .update(normalizeIdentifier(identifier))
    .digest('hex');
}
