# PreVita — arquitetura de referência para dados de saúde com provas em blockchain

> **Status:** arquitetura de referência **em desenvolvimento**. Não está em produção, não foi auditada por terceiros e só usa dados sintéticos. Serve para mostrar, em código testável, as regras descritas na nota técnica da PreVita ao Grupo de Trabalho de Tokenização (GTT) da CVM e em [previtasaude.com.br/prontuario/cvm-249](https://previtasaude.com.br/prontuario/cvm-249).

A regra central é: **nenhum dado pessoal ou clínico vai para a cadeia.** A blockchain recebe só provas: raízes de Merkle de lotes de documentos e eventos de consentimento com identificadores pseudonimizados. O conteúdo clínico fica cifrado na instituição que tem a guarda legal.

| Na cadeia (Hedera Consensus Service) | Fora da cadeia (na instituição) |
|---|---|
| Raiz de Merkle de cada lote, com carimbo de tempo de consenso | Documentos clínicos (HL7 FHIR R4) cifrados com AES-256-GCM |
| Eventos de consentimento: concessão, uso, revogação | Nome, CPF e qualquer identificador em claro |
| Pseudônimos (HMAC-SHA256) e compromissos de documento | Uma chave por documento e um sal por registro |

## Como cada regra aparece no código

| Regra | Arquivo | Teste que a demonstra |
|---|---|---|
| Pseudônimo com hash **com chave**, nunca hash simples de CPF | [`src/pseudonym.js`](src/pseudonym.js) | pseudônimo com chave não é o SHA-256 do CPF |
| Documento cifrado, uma chave por documento; compromisso com sal por registro | [`src/vault.js`](src/vault.js) | documento cifrado só abre com a chave |
| Árvore de Merkle com prova de inclusão (privacidade auditável) | [`src/merkle.js`](src/merkle.js) | prova confirma um registro sem expor os outros |
| Consentimento por finalidade e prazo; revogação é novo evento; cadeia de eventos à prova de alteração | [`src/consent.js`](src/consent.js) | chave só sai com consentimento ativo |
| Eliminação fora da cadeia: destrói chave e sal, apaga o texto cifrado | [`src/vault.js`](src/vault.js) | destruída a chave, o documento não volta |
| Lista fechada de campos que podem ir para a cadeia | [`src/anchor.js`](src/anchor.js) | mensagens só levam campos permitidos |

## Relação com as lacunas apontadas na nota ao GTT

1. **Imutabilidade e eliminação.** A cadeia guarda só compromissos. Eliminar é destruir a chave e o sal: a folha continua na raiz já ancorada, mas não reconstrói nem identifica o conteúdo.
2. **Hash de dado pessoal.** Hash simples de CPF é revertido por força bruta. Aqui o pseudônimo é HMAC com chave do controlador e domínio separado por papel (paciente, destinatário); o compromisso do documento usa sal aleatório por registro.
3. **Consentimento executado por código.** Concessão, uso e revogação são eventos encadeados por hash, com finalidade de uma lista fechada e prazo. A revogação vale a partir do seu registro e não retroage.
4. **Perímetro do valor mobiliário.** Não há token negociável, pagamento, venda de dados nem repasse de receita neste código. O direito de acesso é a concessão registrada, pessoal e revogável.
5. **Cooperação entre autoridades.** A reidentificação é o recálculo do HMAC pelo controlador, mediante requisição da autoridade competente, fora da rede.

## Rodar

Requer Node.js 20 ou superior. Sem dependências.

```bash
npm test
npm run demo
```

Para ancorar de verdade no Hedera Testnet, instale `@hashgraph/sdk` e use `submitToHcs` de [`src/anchor.js`](src/anchor.js) com uma conta de testnet. Os testes não fazem chamadas de rede.

## Limites conhecidos

- `ConsentLedger` reproduz em memória as regras que um smart contract executaria; o contrato em rede ainda não foi escrito.
- `KeyBroker` devolve a chave do documento em claro; em produção ela seria cifrada para a chave pública do destinatário antes de sair da instituição.
- Chaves ficam em memória; em produção, chave de pseudonimização e chaves de documento ficam em HSM ou KMS da instituição.
- Metadados continuam sendo um risco: a frequência e o horário dos eventos de consentimento de um mesmo pseudônimo podem revelar informação. Lotes com intervalo fixo e rotação de pseudônimos por destinatário reduzem, mas não eliminam.
- O token intransferível de direito de acesso, descrito na nota, ainda não está implementado.
- Prazo legal de guarda (Lei 13.787/2018) e pedidos de eliminação precisam de regra de negócio própria, fora deste código.

## Histórico

O protótipo do hackathon de março de 2026 ([lgafraga/previta-mvp](https://github.com/lgafraga/previta-mvp), arquivado) tinha NFT por registro e marketplace de dados. Esse desenho foi descontinuado e não faz parte desta arquitetura.

PreVita Tecnologia em Saúde Ltda. · CNPJ 66.682.737/0001-40 · Salvador/BA · contato@previtasaude.com.br · Licença MIT
