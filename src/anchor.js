// Mensagens ancoradas no Hedera Consensus Service (HCS).
//
// A rede pública registra a ordem e o carimbo de tempo de consenso das
// mensagens, que nenhuma das partes altera sozinha. Só dois tipos de mensagem
// existem, e cada um tem uma lista fechada de campos: raiz de lote e evento de
// consentimento. Qualquer campo fora da lista, ou valor com cara de dado
// pessoal, é recusado antes de sair da instituição.
const FIELDS = {
  batch: ['v', 'kind', 'root', 'count', 'batchId', 'at'],
  consent: ['v', 'kind', 'type', 'hash', 'prev', 'seq', 'patient', 'grantee', 'commitment', 'grantId', 'purpose', 'expiresAt', 'at'],
};

const CPF = /\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/;
const EMAIL = /[^\s@]+@[^\s@]+\.[a-z]{2,}/i;

export function batchMessage({ root, count, batchId, at = Date.now() }) {
  return toMessage({ v: 1, kind: 'batch', root, count, batchId, at });
}

export function consentMessage(event) {
  return toMessage({ v: 1, kind: 'consent', ...event });
}

function toMessage(payload) {
  const allowed = FIELDS[payload.kind];
  const extra = Object.keys(payload).filter((k) => !allowed.includes(k));
  if (extra.length) throw new Error(`Campo não permitido na cadeia: ${extra.join(', ')}`);
  for (const value of Object.values(payload)) {
    if (typeof value === 'string' && (CPF.test(value) || EMAIL.test(value))) {
      throw new Error('Valor com aparência de dado pessoal recusado');
    }
  }
  const message = JSON.stringify(payload);
  // Limite de uma mensagem HCS sem fragmentação.
  if (Buffer.byteLength(message) > 1024) throw new Error('Mensagem acima de 1 KB');
  return message;
}

// Envio real ao HCS. Exige `npm install @hashgraph/sdk` e uma conta de testnet
// (HEDERA_ACCOUNT_ID, HEDERA_PRIVATE_KEY, HCS_TOPIC_ID). Não é usado nos testes.
export async function submitToHcs(message, { accountId, privateKey, topicId, network = 'testnet' }) {
  const { Client, PrivateKey, TopicMessageSubmitTransaction } = await import('@hashgraph/sdk');
  const client = Client.forName(network).setOperator(accountId, PrivateKey.fromStringDer(privateKey));
  try {
    const response = await new TopicMessageSubmitTransaction({ topicId, message }).execute(client);
    const receipt = await response.getReceipt(client);
    return { status: receipt.status.toString(), sequence: receipt.topicSequenceNumber?.toString() };
  } finally {
    client.close();
  }
}
