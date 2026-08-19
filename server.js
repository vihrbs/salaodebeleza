const express  = require('express');
const cors     = require('cors');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const crypto   = require('crypto');

const app = express();
app.use(cors());
// Limite bem generoso — necessário pra importações em lote (ex.: histórico
// de vendas de outro sistema, que pode ter milhares de linhas numa única
// requisição). O padrão do Express (100kb) é pequeno demais pra isso e
// rejeita a requisição antes mesmo de chegar nas rotas.
app.use(express.json({ limit: '15mb' }));

// ── Supabase ─────────────────────────────────────────
const { createClient } = require('@supabase/supabase-js');

// Valida variáveis obrigatórias
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_KEY) {
  console.error('ERRO: SUPABASE_URL e SUPABASE_SERVICE_KEY são obrigatórias!');
  process.exit(1);
}
if (!process.env.MP_ACCESS_TOKEN) {
  console.warn('AVISO: MP_ACCESS_TOKEN não configurado — pagamentos desativados');
}

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
  { auth: { autoRefreshToken: false, persistSession: false } }
);

const JWT_SECRET = process.env.JWT_SECRET || 'beleza_pro_secret_2026';

// ── Helpers de fuso horário (Brasil = UTC-3) ────────
function utcParaMinutosBrasil(dataHoraUTC) {
  // dataHoraUTC vem como string tipo '2026-06-27T16:00:00+00:00'
  var dt = new Date(dataHoraUTC);
  var totalMinUTC = dt.getUTCHours() * 60 + dt.getUTCMinutes();
  var totalMinBrasil = totalMinUTC - 180; // UTC-3
  if (totalMinBrasil < 0) totalMinBrasil += 1440;
  return totalMinBrasil;
}

function adicionarDia(dataISO) {
  var d = new Date(dataISO + 'T12:00:00Z');
  d.setUTCDate(d.getUTCDate() + 1);
  return d.toISOString().split('T')[0];
}

function dataAtualBrasil() {
  var agora = new Date();
  var brasil = new Date(agora.getTime() - 3 * 60 * 60 * 1000);
  return brasil.toISOString().split('T')[0];
}

function minutosAgoraBrasil() {
  var agora = new Date();
  var brasil = new Date(agora.getTime() - 3 * 60 * 60 * 1000);
  return brasil.getUTCHours() * 60 + brasil.getUTCMinutes();
}


// ── Helpers ──────────────────────────────────────────
function slugify(text) {
  return text.toLowerCase()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

async function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token necessário' });
  }
  try {
    const payload = jwt.verify(header.split(' ')[1], JWT_SECRET);
    const { data: usuario } = await supabase
      .from('usuarios').select('id, nome, email, perfil, salao_id, ativo, profissional_id')
      .eq('id', payload.sub).single();
    if (!usuario || !usuario.ativo) return res.status(401).json({ error: 'Usuário inválido' });
    req.user     = usuario;
    req.salao_id = usuario.salao_id;
    next();
  } catch(e) {
    return res.status(401).json({ error: 'Token inválido ou expirado' });
  }
}

// Retorna o profissional_id que deve filtrar os dados deste usuário.
// Admin sem vínculo = null (vê tudo). Usuário custom vinculado = só o próprio.
function profissionalFiltroDoUsuario(user) {
  if (user.perfil === 'admin') return null;
  return user.profissional_id || null;
}

// Middleware de permissão por módulo — bloqueia o acesso no SERVIDOR, não só
// no frontend (esconder um botão não impede alguém de chamar a API direto).
// Admin sempre passa; usuário custom só passa se o módulo estiver na lista
// de permissões salva pra ele em usuario_permissoes.
function requirePermissao(modulo) {
  return async function(req, res, next) {
    if (req.user.perfil === 'admin') return next();
    try {
      const { data: perm } = await supabase.from('usuario_permissoes')
        .select('permissoes').eq('usuario_id', req.user.id).maybeSingle();
      const permissoes = (perm && perm.permissoes) || [];
      if (!permissoes.includes(modulo)) {
        return res.status(403).json({ error: 'Você não tem permissão para acessar este módulo' });
      }
      next();
    } catch(e) {
      res.status(500).json({ error: 'Erro ao verificar permissões' });
    }
  };
}

// ── DEDUPLICAÇÃO NA IMPORTAÇÃO EM LOTE ────────────────
// Usado pelas rotas /lote pra não criar registro repetido quando a pessoa
// importa a mesma planilha duas vezes, ou quando a própria planilha já
// vem com linhas duplicadas.
function normalizarTexto(v) {
  return String(v || '').trim().toLowerCase();
}
function normalizarTelefone(v) {
  return String(v || '').replace(/\D/g, '');
}

// Separa um array em { paraInserir, duplicados } com base numa função que
// calcula a "chave" de cada item — compara tanto contra o que já existe no
// banco (chavesExistentes) quanto duplicidade dentro da própria planilha.
function separarDuplicados(itens, chavesExistentes, calcularChave) {
  const chavesVistas = new Set();
  const paraInserir = [];
  let duplicados = 0;
  for (const item of itens) {
    const chave = calcularChave(item);
    if (!chave || chavesExistentes.has(chave) || chavesVistas.has(chave)) { duplicados++; continue; }
    chavesVistas.add(chave);
    paraInserir.push(item);
  }
  return { paraInserir, duplicados };
}

// ── PREÇO POR DIA DA SEMANA ────────────────────────────
// Serviço pode ter um preço diferente em dias específicos (ex.: Corte custa
// R$55, mas R$45 na Terça/Quarta/Quinta). Guardado em servicos.precos_por_dia
// como um objeto { "2": 45, "3": 45, "4": 45 } — chave é o dia da semana
// (0=domingo ... 6=sábado, igual o Date.getDay() do JavaScript).
// dataHoraISO é interpretado direto da data (sem passar pelo fuso do JS
// Date), senão um agendamento perto da meia-noite poderia cair no dia errado.
function diaDaSemanaBrasil(dataHoraISO) {
  const dataParte = String(dataHoraISO).split('T')[0];
  const [ano, mes, dia] = dataParte.split('-').map(Number);
  return new Date(Date.UTC(ano, mes - 1, dia)).getUTCDay();
}

function precoEfetivoServico(servico, dataHoraISO) {
  const precosPorDia = servico.precos_por_dia || {};
  const diaSemana = diaDaSemanaBrasil(dataHoraISO);
  const precoDoDia = precosPorDia[String(diaSemana)];
  return (precoDoDia !== undefined && precoDoDia !== null) ? Number(precoDoDia) : Number(servico.preco);
}

// ── MAQUININHA DE CARTÃO ─────────────────────────────
// Formas de pagamento que sofrem desconto de taxa de maquininha.
// Precisa bater exatamente com os valores enviados pelo frontend (botões fpg-btn).
const FORMAS_PAGAMENTO_CARTAO = new Set(['Cartão Débito', 'Cartão Crédito']);

// Quando um agendamento é concluído com pagamento no cartão, calcula a taxa da
// maquininha sobre o valor total, divide ao meio (metade fica com o salão,
// metade é descontada do profissional) e abate a parte do profissional
// proporcionalmente da comissão de cada serviço do agendamento.
// Retorna { taxa_total, taxa_profissional } para fins de log/depuração.
async function aplicarTaxaMaquininha(agendamentoId, salaoId, valorTotal, formaPgto) {
  if (!FORMAS_PAGAMENTO_CARTAO.has(formaPgto)) return { taxa_total: 0, taxa_profissional: 0 };
  if (!valorTotal || valorTotal <= 0) return { taxa_total: 0, taxa_profissional: 0 };

  const { data: salao } = await supabase.from('saloes')
    .select('configuracoes').eq('id', salaoId).single();
  const cfg = salao?.configuracoes || {};
  const ehDebito = formaPgto === 'Cartão Débito';
  // taxa_maquininha_pct (campo antigo) fica como fallback pra quem configurou
  // antes de débito/crédito virarem campos separados.
  const pct = Number(
    ehDebito
      ? (cfg.taxa_maquininha_debito_pct ?? cfg.taxa_maquininha_pct ?? 0)
      : (cfg.taxa_maquininha_credito_pct ?? cfg.taxa_maquininha_pct ?? 0)
  );
  if (!pct || pct <= 0) return { taxa_total: 0, taxa_profissional: 0 };

  const taxaTotal = Math.round(valorTotal * pct / 100 * 100) / 100;
  const taxaProfissional = Math.round((taxaTotal / 2) * 100) / 100; // metade da taxa

  const { data: servicos } = await supabase.from('agendamento_servicos')
    .select('id, preco, comissao_valor').eq('agendamento_id', agendamentoId);

  if (servicos && servicos.length) {
    for (const s of servicos) {
      const proporcao = Number(s.preco || 0) / valorTotal;
      const deducao = Math.round(taxaProfissional * proporcao * 100) / 100;
      const novaComissao = Math.max(0, Number(s.comissao_valor || 0) - deducao);
      await supabase.from('agendamento_servicos')
        .update({ comissao_valor: novaComissao }).eq('id', s.id);
    }
  }

  try {
    await supabase.from('agendamentos')
      .update({ taxa_maquininha_valor: taxaTotal }).eq('id', agendamentoId);
  } catch(e) { /* coluna pode não existir ainda se a migration não rodou */ }

  return { taxa_total: taxaTotal, taxa_profissional: taxaProfissional };
}

// ── PARCELAMENTO DE PRODUTO PRO PROFISSIONAL ─────────
// Divide um valor total em N parcelas mensais. A última parcela absorve
// qualquer diferença de arredondamento, garantindo que a soma bate exatamente
// com o valor total (evita perder ou sobrar centavos).
function gerarParcelas(valorTotal, numParcelas, dataCompraISO) {
  const valorParcela = Math.floor((valorTotal / numParcelas) * 100) / 100;
  const parcelas = [];
  let somaParcial = 0;
  const [ano, mes, dia] = dataCompraISO.split('-').map(Number);

  for (let i = 1; i <= numParcelas; i++) {
    const mesVencimento = mes - 1 + (i - 1); // 0-indexed pro Date.UTC
    const venc = new Date(Date.UTC(ano, mesVencimento, dia));
    let valor = valorParcela;
    if (i === numParcelas) valor = Math.round((valorTotal - somaParcial) * 100) / 100;
    somaParcial = Math.round((somaParcial + valor) * 100) / 100;
    parcelas.push({
      numero_parcela: i,
      valor,
      vencimento: venc.toISOString().split('T')[0],
      status: 'pendente'
    });
  }
  return parcelas;
}

// ── Health ───────────────────────────────────────────
app.get('/',       (req, res) => res.json({ mensagem: 'Beleza Pro API rodando' }));
app.get('/health', (req, res) => res.json({ status: 'ok', version: '3.9.1-preview-preco-e-grade-corrigida' }));

// ── VERIFICAÇÃO DE E-MAIL ─────────────────────────────
function emailValido(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || '').trim());
}

function gerarCodigoVerificacao() {
  return String(Math.floor(100000 + Math.random() * 900000)); // 6 dígitos
}

function expiracaoCodigoVerificacao() {
  return new Date(Date.now() + 15 * 60 * 1000); // 15 minutos
}

// O Resend devolve o motivo real do erro no corpo da resposta (geralmente
// JSON com um campo "message", ex: domínio não verificado, chave sem
// permissão pra esse remetente, etc.). Extrai isso pra mostrar pro admin em
// vez de só o código de status HTTP, que sozinho não diz muita coisa.
function extrairMensagemErroResend(textoResposta) {
  try {
    const json = JSON.parse(textoResposta);
    return json.message || json.error || textoResposta || 'sem detalhes';
  } catch(e) {
    return textoResposta || 'sem detalhes';
  }
}

async function enviarCodigoVerificacao(email, nome, codigo) {
  const RESEND_KEY = process.env.RESEND_API_KEY || '';
  if (!RESEND_KEY) {
    console.log('RESEND_API_KEY não configurado — código de verificação para ' + email + ': ' + codigo);
    return { enviado: false, motivo: 'RESEND_API_KEY não configurado' };
  }
  // Usa o remetente de teste do Resend por padrão — funciona sem precisar
  // verificar domínio. Defina RESEND_FROM_EMAIL no Railway pra usar um
  // remetente com o seu próprio domínio verificado no Resend.
  const remetente = process.env.RESEND_FROM_EMAIL || 'Beleza Pro <onboarding@resend.dev>';
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + RESEND_KEY },
      body: JSON.stringify({
        from: remetente,
        to: [email],
        subject: 'Seu código de verificação — Beleza Pro',
        text: 'Olá ' + nome + '!\n\nSeu código de verificação é: ' + codigo + '\n\nEle expira em 15 minutos. Se você não pediu isso, pode ignorar este e-mail.'
      })
    });
    if (!r.ok) {
      const detalheTexto = await r.text().catch(() => '');
      const detalheLegivel = extrairMensagemErroResend(detalheTexto);
      console.error('Resend recusou o envio do código (status ' + r.status + '): ' + detalheTexto);
      return { enviado: false, motivo: 'Resend (' + r.status + '): ' + detalheLegivel };
    }
    return { enviado: true };
  } catch(e) {
    console.error('Erro ao enviar código de verificação:', e.message);
    return { enviado: false, motivo: e.message };
  }
}

// ═══════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════

// REGISTER — cria salão + admin
app.post('/api/auth/register', async (req, res) => {
  const { nome_salao, nome, email, senha, telefone } = req.body;
  if (!nome_salao || !nome || !email || !senha) {
    return res.status(422).json({ error: 'Preencha todos os campos obrigatórios' });
  }
  if (!emailValido(email)) return res.status(422).json({ error: 'Informe um e-mail válido' });
  try {
    const { data: existe } = await supabase
      .from('usuarios').select('id').eq('email', email).single();
    if (existe) return res.status(409).json({ error: 'Email já cadastrado' });

    const senha_hash = await bcrypt.hash(senha, 12);

    let slug = slugify(nome_salao);
    const { count } = await supabase
      .from('saloes').select('id', { count: 'exact' }).like('slug', slug + '%');
    if (count > 0) slug = slug + '-' + (count + 1);

    const trial_ate = new Date();
    trial_ate.setDate(trial_ate.getDate() + 14);

    const { data: plano } = await supabase
      .from('planos').select('id').eq('nome', 'Starter').single();

    const { data: salao, error: salaoErr } = await supabase
      .from('saloes')
      .insert({ nome: nome_salao, slug, telefone, plano_id: plano?.id, trial_ate })
      .select().single();
    if (salaoErr) throw salaoErr;

    const codigoVerificacao = gerarCodigoVerificacao();

    const { data: usuario, error: userErr } = await supabase
      .from('usuarios')
      .insert({
        salao_id: salao.id, nome, email, senha_hash, perfil: 'admin',
        email_verificado: false, codigo_verificacao: codigoVerificacao,
        codigo_verificacao_expira: expiracaoCodigoVerificacao()
      })
      .select('id, nome, email, perfil, salao_id, email_verificado').single();
    if (userErr) throw userErr;

    const token = jwt.sign({ sub: usuario.id }, JWT_SECRET, { expiresIn: '7d' });

    // Notificação de novo cadastro (não bloqueia a resposta, não é crítico)
    notificarNovoCadastro(salao.nome, nome, email, telefone).catch(e =>
      console.log('Notificação falhou (não crítico):', e.message)
    );

    // Código de verificação: espera o resultado real do envio, pra devolver
    // pro frontend se deu certo ou não (em vez de falhar em silêncio)
    const resultadoEmail = await enviarCodigoVerificacao(email, nome, codigoVerificacao)
      .catch(e => ({ enviado: false, motivo: e.message }));

    res.status(201).json({
      token, usuario: { ...usuario, saloes: salao }, salao,
      email_enviado: resultadoEmail.enviado,
      email_motivo_falha: resultadoEmail.enviado ? null : resultadoEmail.motivo
    });
  } catch(e) {
    console.error('Register error:', e);
    res.status(500).json({ error: 'Erro ao criar conta: ' + e.message });
  }
});

// ── NOTIFICAÇÕES ─────────────────────────────────────
async function notificarNovoCadastro(nomeSalao, nomeUser, email, telefone) {
  const RESEND_KEY  = process.env.RESEND_API_KEY || '';
  const EMAIL_ADMIN = process.env.ADMIN_EMAIL || '';
  const WPP_NUMERO  = process.env.ADMIN_WHATSAPP || '';

  const msg = `🎉 Novo cadastro no Beleza Pro!

Salão: ${nomeSalao}
Nome: ${nomeUser}
Email: ${email}
Telefone: ${telefone || 'não informado'}
Data: ${new Date().toLocaleString('pt-BR')}

Acesse o Railway para ver os dados completos.`;

  // Notificação por E-mail via Resend
  if (RESEND_KEY && EMAIL_ADMIN) {
    try {
      const remetente = process.env.RESEND_FROM_EMAIL || 'Beleza Pro <onboarding@resend.dev>';
      const r = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + RESEND_KEY },
        body: JSON.stringify({
          from: remetente,
          to: [EMAIL_ADMIN],
          subject: '🎉 Novo cadastro: ' + nomeSalao,
          text: msg
        })
      });
      if (!r.ok) {
        const detalhe = await r.text().catch(() => '');
        console.error('Resend recusou a notificação de cadastro (status ' + r.status + '): ' + detalhe);
      } else {
        console.log('Email de notificação enviado para', EMAIL_ADMIN);
      }
    } catch(e) { console.error('Erro ao enviar email:', e.message); }
  }

  // Notificação por Telegram
  const TELEGRAM_TOKEN   = process.env.TELEGRAM_BOT_TOKEN || '';
  const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID   || '';
  if (TELEGRAM_TOKEN && TELEGRAM_CHAT_ID) {
    try {
      await fetch('https://api.telegram.org/bot' + TELEGRAM_TOKEN + '/sendMessage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: TELEGRAM_CHAT_ID, text: msg })
      });
      console.log('Telegram notificação enviada');
    } catch(e) { console.error('Erro ao enviar Telegram:', e.message); }
  }
}

// LOGIN
app.post('/api/auth/login', async (req, res) => {
  const { email, senha } = req.body;
  if (!email || !senha) return res.status(422).json({ error: 'Email e senha obrigatórios' });
  try {
    const { data: usuario } = await supabase
      .from('usuarios')
      .select('id, nome, email, senha_hash, perfil, ativo, salao_id, profissional_id, email_verificado, saloes(id, nome, slug, trial_ate)')
      .eq('email', email).single();
    if (!usuario) return res.status(401).json({ error: 'Email ou senha incorretos' });
    if (!usuario.ativo) return res.status(403).json({ error: 'Conta desativada' });

    const ok = await bcrypt.compare(senha, usuario.senha_hash);
    if (!ok) return res.status(401).json({ error: 'Email ou senha incorretos' });

    await supabase.from('usuarios').update({ ultimo_login: new Date() }).eq('id', usuario.id);

    const token = jwt.sign({ sub: usuario.id }, JWT_SECRET, { expiresIn: '7d' });
    const { senha_hash, ...userSafe } = usuario;
    // Retorna permissões do usuário
    if (userSafe.perfil === 'admin') {
      userSafe.permissoes = ['dashboard','agenda','clientes','financeiro','estoque','comissoes','profissionais','servicos','pacotes','config'];
    } else {
      // Busca permissões customizadas do banco
      try {
        const { data: perm } = await supabase.from('usuario_permissoes')
          .select('permissoes').eq('usuario_id', usuario.id).maybeSingle();
        userSafe.permissoes = (perm && perm.permissoes && perm.permissoes.length)
          ? perm.permissoes
          : ['dashboard','agenda','clientes','estoque','comissoes'];
      } catch(e) {
        userSafe.permissoes = ['dashboard','agenda','clientes','estoque','comissoes'];
      }
    }
    res.json({ token, usuario: userSafe });
  } catch(e) {
    res.status(500).json({ error: 'Erro ao fazer login' });
  }
});

// ME
app.get('/api/auth/me', auth, async (req, res) => {
  const { data } = await supabase
    .from('usuarios')
    .select('id, nome, email, perfil, profissional_id, email_verificado, ultimo_login, saloes(id, nome, slug, trial_ate)')
    .eq('id', req.user.id).single();
  res.json(data);
});

// Confirma o código de verificação enviado por e-mail
app.post('/api/auth/verificar-email', async (req, res) => {
  const { email, codigo } = req.body;
  if (!email || !codigo) return res.status(422).json({ error: 'E-mail e código são obrigatórios' });
  try {
    const { data: usuario } = await supabase.from('usuarios')
      .select('id, email_verificado, codigo_verificacao, codigo_verificacao_expira')
      .eq('email', email).single();
    if (!usuario) return res.status(404).json({ error: 'Usuário não encontrado' });
    if (usuario.email_verificado) return res.status(409).json({ error: 'Este e-mail já foi verificado' });
    if (!usuario.codigo_verificacao || String(usuario.codigo_verificacao) !== String(codigo)) {
      return res.status(422).json({ error: 'Código inválido' });
    }
    if (usuario.codigo_verificacao_expira && new Date(usuario.codigo_verificacao_expira) < new Date()) {
      return res.status(422).json({ error: 'Código expirado. Solicite um novo.' });
    }
    await supabase.from('usuarios').update({
      email_verificado: true, codigo_verificacao: null, codigo_verificacao_expira: null
    }).eq('id', usuario.id);
    res.json({ message: 'E-mail verificado com sucesso!' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Reenvia um novo código de verificação
app.post('/api/auth/reenviar-codigo', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(422).json({ error: 'E-mail é obrigatório' });
  try {
    const { data: usuario } = await supabase.from('usuarios')
      .select('id, nome, email_verificado').eq('email', email).single();
    if (!usuario) return res.status(404).json({ error: 'Usuário não encontrado' });
    if (usuario.email_verificado) return res.status(409).json({ error: 'Este e-mail já foi verificado' });

    const codigo = gerarCodigoVerificacao();
    await supabase.from('usuarios').update({
      codigo_verificacao: codigo, codigo_verificacao_expira: expiracaoCodigoVerificacao()
    }).eq('id', usuario.id);

    const resultadoEmail = await enviarCodigoVerificacao(email, usuario.nome, codigo)
      .catch(e => ({ enviado: false, motivo: e.message }));

    if (!resultadoEmail.enviado) {
      return res.status(502).json({ error: 'Não foi possível enviar o e-mail: ' + resultadoEmail.motivo });
    }
    res.json({ message: 'Código reenviado! Confira sua caixa de entrada.' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── ESQUECI MINHA SENHA ────────────────────────────────
function gerarTokenReset() {
  return crypto.randomBytes(32).toString('hex');
}

function expiracaoTokenReset() {
  return new Date(Date.now() + 60 * 60 * 1000); // 1 hora
}

async function enviarEmailRedefinicaoSenha(email, nome, token) {
  const link = 'https://belezaprooficial.com.br/painel.html?redefinir_senha=' + token;
  const RESEND_KEY = process.env.RESEND_API_KEY || '';
  if (!RESEND_KEY) {
    console.log('RESEND_API_KEY não configurado — link de redefinição de senha para ' + email + ': ' + link);
    return { enviado: false, motivo: 'RESEND_API_KEY não configurado' };
  }
  const remetente = process.env.RESEND_FROM_EMAIL || 'Beleza Pro <onboarding@resend.dev>';
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + RESEND_KEY },
      body: JSON.stringify({
        from: remetente,
        to: [email],
        subject: 'Redefinir sua senha — Beleza Pro',
        text: 'Olá ' + nome + '!\n\nClique no link abaixo pra escolher uma nova senha (válido por 1 hora):\n\n' + link + '\n\nSe você não pediu isso, pode ignorar este e-mail — sua senha continua a mesma.'
      })
    });
    if (!r.ok) {
      const detalheTexto = await r.text().catch(() => '');
      const detalheLegivel = extrairMensagemErroResend(detalheTexto);
      console.error('Resend recusou o envio do link de redefinição (status ' + r.status + '): ' + detalheTexto);
      return { enviado: false, motivo: 'Resend (' + r.status + '): ' + detalheLegivel };
    }
    return { enviado: true };
  } catch(e) {
    console.error('Erro ao enviar link de redefinição:', e.message);
    return { enviado: false, motivo: e.message };
  }
}

// ── NOTIFICAÇÕES PRO PROFISSIONAL (agendamento novo / comissão fechada) ──
// Genérico: monta e envia um e-mail simples via Resend. Sempre "best-effort"
// — nunca deve impedir a operação principal (criar agendamento, fechar
// comissão) de completar, mesmo se o envio falhar.
async function enviarEmailSimples(email, assunto, corpo) {
  if (!email) return { enviado: false, motivo: 'Sem e-mail cadastrado' };
  const RESEND_KEY = process.env.RESEND_API_KEY || '';
  if (!RESEND_KEY) return { enviado: false, motivo: 'RESEND_API_KEY não configurado' };
  const remetente = process.env.RESEND_FROM_EMAIL || 'Beleza Pro <onboarding@resend.dev>';
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + RESEND_KEY },
      body: JSON.stringify({ from: remetente, to: [email], subject: assunto, text: corpo })
    });
    if (!r.ok) {
      const detalheTexto = await r.text().catch(() => '');
      const detalheLegivel = extrairMensagemErroResend(detalheTexto);
      console.error('Resend recusou notificação (status ' + r.status + '): ' + detalheTexto);
      return { enviado: false, motivo: 'Resend (' + r.status + '): ' + detalheLegivel };
    }
    return { enviado: true };
  } catch(e) {
    console.error('Erro ao enviar notificação:', e.message);
    return { enviado: false, motivo: e.message };
  }
}

function formatarDataHoraBrasil(dataHoraISO) {
  const dt = new Date(dataHoraISO);
  const data = dt.toLocaleDateString('pt-BR', { timeZone: 'America/Sao_Paulo' });
  const hora = dt.toLocaleTimeString('pt-BR', { timeZone: 'America/Sao_Paulo', hour: '2-digit', minute: '2-digit' });
  return { data, hora };
}

// Avisa o profissional que ganhou um agendamento novo
async function notificarProfissionalNovoAgendamento(email, nomeProfissional, nomeCliente, dataHoraISO, servicosNomes, valorTotal) {
  const { data, hora } = formatarDataHoraBrasil(dataHoraISO);
  const listaServicos = (servicosNomes && servicosNomes.length) ? servicosNomes.join(', ') : 'Serviço';
  const valorFmt = 'R$ ' + Number(valorTotal || 0).toLocaleString('pt-BR', { minimumFractionDigits: 2 });
  const corpo = 'Olá ' + nomeProfissional + '!\n\n' +
    'Você tem um novo agendamento:\n\n' +
    'Cliente: ' + nomeCliente + '\n' +
    'Data: ' + data + ' às ' + hora + '\n' +
    'Serviço(s): ' + listaServicos + '\n' +
    'Valor: ' + valorFmt + '\n\n' +
    '— Beleza Pro';
  return enviarEmailSimples(email, '📅 Novo agendamento — ' + nomeCliente, corpo);
}

// Avisa o profissional de uma série de agendamentos recorrentes de uma vez (evita spam de e-mails)
async function notificarProfissionalRecorrencia(email, nomeProfissional, nomeCliente, agendamentosCriados, servicosNomes) {
  const listaServicos = (servicosNomes && servicosNomes.length) ? servicosNomes.join(', ') : 'Serviço';
  const listaDatas = agendamentosCriados.map(a => {
    const { data, hora } = formatarDataHoraBrasil(a.data_hora);
    return '- ' + data + ' às ' + hora;
  }).join('\n');
  const corpo = 'Olá ' + nomeProfissional + '!\n\n' +
    'Você tem ' + agendamentosCriados.length + ' novos agendamentos com ' + nomeCliente + ' (' + listaServicos + '):\n\n' +
    listaDatas + '\n\n— Beleza Pro';
  return enviarEmailSimples(email, '📅 ' + agendamentosCriados.length + ' novos agendamentos — ' + nomeCliente, corpo);
}

// Avisa o profissional que a comissão dele foi fechada/paga
async function notificarProfissionalComissaoFechada(email, nomeProfissional, valorComissao, periodoInicio, periodoFim) {
  const valorFmt = 'R$ ' + Number(valorComissao || 0).toLocaleString('pt-BR', { minimumFractionDigits: 2 });
  const corpo = 'Olá ' + nomeProfissional + '!\n\n' +
    'Sua comissão do período de ' + periodoInicio + ' a ' + periodoFim + ' foi fechada.\n\n' +
    'Valor: ' + valorFmt + '\n\n— Beleza Pro';
  return enviarEmailSimples(email, '💸 Comissão fechada — ' + valorFmt, corpo);
}

// Pede o link de redefinição. Por segurança, SEMPRE responde com sucesso —
// não revela se o e-mail existe ou não no sistema.
app.post('/api/auth/esqueci-senha', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(422).json({ error: 'E-mail é obrigatório' });
  try {
    const { data: usuario } = await supabase.from('usuarios')
      .select('id, nome, ativo').eq('email', email).single();
    if (usuario && usuario.ativo) {
      const token = gerarTokenReset();
      await supabase.from('usuarios').update({
        reset_senha_token: token, reset_senha_expira: expiracaoTokenReset()
      }).eq('id', usuario.id);
      enviarEmailRedefinicaoSenha(email, usuario.nome, token).catch(() => {});
    }
    res.json({ message: 'Se este e-mail estiver cadastrado, você vai receber um link pra redefinir a senha.' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Confirma o token e define a nova senha
app.post('/api/auth/redefinir-senha', async (req, res) => {
  const { token, senha } = req.body;
  if (!token || !senha) return res.status(422).json({ error: 'Token e nova senha são obrigatórios' });
  if (String(senha).length < 6) return res.status(422).json({ error: 'Senha deve ter pelo menos 6 caracteres' });
  try {
    const { data: usuario } = await supabase.from('usuarios')
      .select('id, reset_senha_token, reset_senha_expira')
      .eq('reset_senha_token', token).maybeSingle();
    if (!usuario) return res.status(422).json({ error: 'Link inválido ou já utilizado' });
    if (usuario.reset_senha_expira && new Date(usuario.reset_senha_expira) < new Date()) {
      return res.status(422).json({ error: 'Link expirado. Solicite um novo.' });
    }
    const senha_hash = await bcrypt.hash(senha, 12);
    await supabase.from('usuarios').update({
      senha_hash, reset_senha_token: null, reset_senha_expira: null
    }).eq('id', usuario.id);
    res.json({ message: 'Senha redefinida com sucesso!' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Troca a própria senha já logado, exigindo a senha atual (diferente do
// "esqueci minha senha", que não precisa da senha antiga)
app.post('/api/auth/alterar-senha', auth, async (req, res) => {
  const { senha_atual, senha_nova } = req.body;
  if (!senha_atual || !senha_nova) return res.status(422).json({ error: 'Informe a senha atual e a nova senha' });
  if (String(senha_nova).length < 6) return res.status(422).json({ error: 'A nova senha deve ter pelo menos 6 caracteres' });
  try {
    const { data: usuario } = await supabase.from('usuarios')
      .select('id, senha_hash').eq('id', req.user.id).single();
    if (!usuario) return res.status(404).json({ error: 'Usuário não encontrado' });

    const confere = await bcrypt.compare(senha_atual, usuario.senha_hash);
    // Usa 403 (não 401) de propósito — 401 é interceptado globalmente no
    // frontend como "sessão expirada" e desloga o usuário, o que aqui seria
    // errado: a sessão continua válida, só a senha atual digitada é que
    // está incorreta.
    if (!confere) return res.status(403).json({ error: 'Senha atual incorreta' });

    const senha_hash = await bcrypt.hash(senha_nova, 12);
    await supabase.from('usuarios').update({ senha_hash }).eq('id', usuario.id);
    res.json({ message: 'Senha alterada com sucesso!' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════
// PROFISSIONAIS
// ═══════════════════════════════════════════════════
app.get('/api/profissionais', auth, async (req, res) => {
  const { data, error } = await supabase
    .from('profissionais').select('*')
    .eq('salao_id', req.salao_id).eq('ativo', true).order('nome');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data || []);
});

app.post('/api/profissionais', auth, requirePermissao('profissionais'), async (req, res) => {
  const { data, error } = await supabase
    .from('profissionais')
    .insert({ ...req.body, salao_id: req.salao_id })
    .select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});

// Importa vários profissionais de uma vez (importação de outro sistema)
app.post('/api/profissionais/lote', auth, requirePermissao('profissionais'), async (req, res) => {
  const { profissionais } = req.body;
  if (!Array.isArray(profissionais) || !profissionais.length) {
    return res.status(422).json({ error: 'Envie uma lista de profissionais em "profissionais"' });
  }
  if (profissionais.length > 20000) return res.status(422).json({ error: 'Máximo de 20.000 registros por importação' });

  function chaveProfissional(p) { return p.nome ? 'nome:' + normalizarTexto(p.nome) : null; }

  const { data: existentes } = await supabase.from('profissionais')
    .select('nome').eq('salao_id', req.salao_id).eq('ativo', true);
  const chavesExistentes = new Set((existentes || []).map(chaveProfissional).filter(Boolean));
  const { paraInserir, duplicados } = separarDuplicados(profissionais, chavesExistentes, chaveProfissional);

  if (!paraInserir.length) {
    return res.status(200).json({ message: 'Nenhum profissional novo — todos já existiam ou estavam duplicados na planilha.', total: 0, duplicados });
  }

  const TAMANHO_BLOCO = 500;
  let totalInseridos = 0;
  try {
    for (let i = 0; i < paraInserir.length; i += TAMANHO_BLOCO) {
      const bloco = paraInserir.slice(i, i + TAMANHO_BLOCO).map(p => ({ ...p, salao_id: req.salao_id }));
      const { error } = await supabase.from('profissionais').insert(bloco);
      if (error) throw error;
      totalInseridos += bloco.length;
    }
    res.status(201).json({
      message: totalInseridos + ' profissional(is) importado(s)' + (duplicados ? ', ' + duplicados + ' duplicado(s) ignorado(s)' : '') + '!',
      total: totalInseridos, duplicados
    });
  } catch(e) {
    res.status(500).json({ error: 'Erro ao importar em lote (parou em ' + totalInseridos + ' de ' + paraInserir.length + '): ' + e.message });
  }
});

app.put('/api/profissionais/:id', auth, requirePermissao('profissionais'), async (req, res) => {
  const { data, error } = await supabase
    .from('profissionais').update(req.body)
    .eq('id', req.params.id).eq('salao_id', req.salao_id).select().single();
  if (error || !data) return res.status(404).json({ error: 'Não encontrado' });
  res.json(data);
});

app.delete('/api/profissionais/:id', auth, requirePermissao('profissionais'), async (req, res) => {
  await supabase.from('profissionais').update({ ativo: false })
    .eq('id', req.params.id).eq('salao_id', req.salao_id);
  res.json({ message: 'Desativado' });
});

// ── Compras parceladas (venda de produto pro profissional) ─────
// Registra uma venda de produto (ou item avulso) pro profissional, dividida
// em N parcelas mensais. Só o admin pode registrar/gerenciar essas vendas;
// o próprio profissional pode consultar as suas.
app.post('/api/profissionais/:id/compras', auth, async (req, res) => {
  if (req.user.perfil !== 'admin') {
    return res.status(403).json({ error: 'Apenas o administrador pode registrar vendas parceladas' });
  }
  const { produto_id, descricao, valor_total, num_parcelas, data_compra } = req.body;
  const valorTotal = Number(valor_total);
  const numParcelas = parseInt(num_parcelas) || 1;

  if (!valorTotal || valorTotal <= 0) return res.status(422).json({ error: 'Valor total inválido' });
  if (numParcelas < 1 || numParcelas > 24) return res.status(422).json({ error: 'Número de parcelas deve ser entre 1 e 24' });
  if (!descricao && !produto_id) return res.status(422).json({ error: 'Informe um produto ou uma descrição' });

  try {
    const { data: prof } = await supabase.from('profissionais')
      .select('id').eq('id', req.params.id).eq('salao_id', req.salao_id).single();
    if (!prof) return res.status(404).json({ error: 'Profissional não encontrado' });

    let descricaoFinal = descricao || null;
    if (produto_id) {
      const { data: produto } = await supabase.from('produtos')
        .select('id, nome, qtd_atual').eq('id', produto_id).eq('salao_id', req.salao_id).single();
      if (!produto) return res.status(404).json({ error: 'Produto não encontrado' });
      if (Number(produto.qtd_atual) < 1) return res.status(422).json({ error: 'Produto sem estoque disponível' });
      descricaoFinal = descricaoFinal || produto.nome;
      // Debita 1 unidade do estoque — o produto está saindo pro profissional
      await supabase.from('produtos')
        .update({ qtd_atual: Number(produto.qtd_atual) - 1 }).eq('id', produto_id);
    }

    const dataCompraFinal = data_compra || new Date().toISOString().split('T')[0];

    const { data: compra, error: compraErr } = await supabase.from('compras_profissional')
      .insert({
        salao_id: req.salao_id, profissional_id: req.params.id, produto_id: produto_id || null,
        descricao: descricaoFinal, valor_total: valorTotal, num_parcelas: numParcelas,
        data_compra: dataCompraFinal
      }).select().single();
    if (compraErr) throw compraErr;

    const parcelas = gerarParcelas(valorTotal, numParcelas, dataCompraFinal)
      .map(p => ({ ...p, compra_id: compra.id }));
    const { data: parcelasInseridas, error: parcErr } = await supabase
      .from('parcelas_compra_profissional').insert(parcelas).select();
    if (parcErr) throw parcErr;

    res.status(201).json({ ...compra, parcelas: parcelasInseridas || parcelas });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Lista as compras parceladas de um profissional (com as parcelas de cada uma)
app.get('/api/profissionais/:id/compras', auth, async (req, res) => {
  const filtroObrigatorio = profissionalFiltroDoUsuario(req.user);
  if (filtroObrigatorio && filtroObrigatorio !== req.params.id) {
    return res.status(403).json({ error: 'Acesso negado' });
  }
  try {
    const { data, error } = await supabase.from('compras_profissional')
      .select('*, parcelas_compra_profissional(*)')
      .eq('salao_id', req.salao_id).eq('profissional_id', req.params.id)
      .order('data_compra', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Marca uma parcela específica como paga
app.patch('/api/parcelas/:id/pagar', auth, async (req, res) => {
  if (req.user.perfil !== 'admin') {
    return res.status(403).json({ error: 'Apenas o administrador pode confirmar pagamento de parcelas' });
  }
  try {
    const { data: parcela } = await supabase.from('parcelas_compra_profissional')
      .select('id, status, compra_id, compras_profissional!inner(salao_id)')
      .eq('id', req.params.id).eq('compras_profissional.salao_id', req.salao_id).maybeSingle();
    if (!parcela) return res.status(404).json({ error: 'Parcela não encontrada' });
    if (parcela.status === 'pago') return res.status(409).json({ error: 'Esta parcela já está paga' });

    const { data, error } = await supabase.from('parcelas_compra_profissional')
      .update({ status: 'pago', pago_em: new Date() })
      .eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json(data);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════
// SERVIÇOS
// ═══════════════════════════════════════════════════
app.get('/api/servicos', auth, async (req, res) => {
  const { data, error } = await supabase
    .from('servicos').select('*')
    .eq('salao_id', req.salao_id).eq('ativo', true).order('nome');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data || []);
});

app.post('/api/servicos', auth, requirePermissao('servicos'), async (req, res) => {
  const { data, error } = await supabase
    .from('servicos')
    .insert({ ...req.body, salao_id: req.salao_id })
    .select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});

// Importa vários serviços de uma vez (importação de outro sistema)
app.post('/api/servicos/lote', auth, requirePermissao('servicos'), async (req, res) => {
  const { servicos } = req.body;
  if (!Array.isArray(servicos) || !servicos.length) {
    return res.status(422).json({ error: 'Envie uma lista de serviços em "servicos"' });
  }
  if (servicos.length > 20000) return res.status(422).json({ error: 'Máximo de 20.000 registros por importação' });

  function chaveServico(s) { return s.nome ? 'nome:' + normalizarTexto(s.nome) : null; }

  const { data: existentes } = await supabase.from('servicos')
    .select('nome').eq('salao_id', req.salao_id).eq('ativo', true);
  const chavesExistentes = new Set((existentes || []).map(chaveServico).filter(Boolean));
  const { paraInserir, duplicados } = separarDuplicados(servicos, chavesExistentes, chaveServico);

  if (!paraInserir.length) {
    return res.status(200).json({ message: 'Nenhum serviço novo — todos já existiam ou estavam duplicados na planilha.', total: 0, duplicados });
  }

  const TAMANHO_BLOCO = 500;
  let totalInseridos = 0;
  try {
    for (let i = 0; i < paraInserir.length; i += TAMANHO_BLOCO) {
      const bloco = paraInserir.slice(i, i + TAMANHO_BLOCO).map(s => ({ ...s, salao_id: req.salao_id }));
      const { error } = await supabase.from('servicos').insert(bloco);
      if (error) throw error;
      totalInseridos += bloco.length;
    }
    res.status(201).json({
      message: totalInseridos + ' serviço(s) importado(s)' + (duplicados ? ', ' + duplicados + ' duplicado(s) ignorado(s)' : '') + '!',
      total: totalInseridos, duplicados
    });
  } catch(e) {
    res.status(500).json({ error: 'Erro ao importar em lote (parou em ' + totalInseridos + ' de ' + paraInserir.length + '): ' + e.message });
  }
});

app.put('/api/servicos/:id', auth, requirePermissao('servicos'), async (req, res) => {
  const { data, error } = await supabase
    .from('servicos').update(req.body)
    .eq('id', req.params.id).eq('salao_id', req.salao_id).select().single();
  if (error || !data) return res.status(404).json({ error: 'Não encontrado' });
  res.json(data);
});

app.delete('/api/servicos/:id', auth, requirePermissao('servicos'), async (req, res) => {
  await supabase.from('servicos').update({ ativo: false })
    .eq('id', req.params.id).eq('salao_id', req.salao_id);
  res.json({ message: 'Desativado' });
});

// ═══════════════════════════════════════════════════
// PACOTES DE SERVIÇO (modelo Trinks)
// ═══════════════════════════════════════════════════
// Um "pacote" é um modelo (template) vendável: um conjunto de serviços com um
// número de sessões cada, por um preço fechado. Quando o cliente compra um
// pacote, cria-se uma instância (pacotes_clientes) com o saldo de sessões
// disponível, que pode ser consumido em agendamentos futuros.

app.get('/api/pacotes', auth, async (req, res) => {
  const { data, error } = await supabase.from('pacotes')
    .select('*').eq('salao_id', req.salao_id).eq('ativo', true).order('nome');
  if (error) return res.status(500).json({ error: error.message });
  // Sinaliza pacotes sem nenhum serviço configurado (ex.: vieram de uma
  // importação que só trouxe nome+preço) — a pessoa precisa completar depois
  const comSinal = (data || []).map(p => ({ ...p, precisa_configurar: !p.servicos || p.servicos.length === 0 }));
  res.json(comSinal);
});

app.post('/api/pacotes', auth, async (req, res) => {
  if (req.user.perfil !== 'admin') return res.status(403).json({ error: 'Apenas o administrador pode criar pacotes' });
  const { nome, descricao, preco, validade_dias, servicos, verificar_duplicidade } = req.body;
  if (!nome || !preco) {
    return res.status(422).json({ error: 'Nome e preço são obrigatórios' });
  }

  // Só checa duplicidade quando pedido explicitamente (usado pela
  // importação) — não muda o comportamento de quem cria um pacote manual
  // pelo botão "Novo Pacote", que sempre funcionou sem essa checagem.
  if (verificar_duplicidade) {
    const { data: existente } = await supabase.from('pacotes')
      .select('id').eq('salao_id', req.salao_id).eq('ativo', true)
      .ilike('nome', String(nome).trim()).maybeSingle();
    if (existente) {
      return res.status(200).json({ duplicado: true, message: 'Pacote "' + nome + '" já existe — ignorado na importação.' });
    }
  }

  // Serviços são opcionais na criação — permite importar pacotes de outro
  // sistema que só trazem nome+preço, sem o detalhamento de sessões. Quando
  // informados, cada um precisa ter estrutura válida.
  const servicosFinal = Array.isArray(servicos) ? servicos : [];
  for (const s of servicosFinal) {
    if (!s.servico_id || !s.qtd_sessoes || s.qtd_sessoes < 1) {
      return res.status(422).json({ error: 'Cada serviço do pacote precisa de servico_id e ao menos 1 sessão' });
    }
  }
  try {
    const { data, error } = await supabase.from('pacotes')
      .insert({
        salao_id: req.salao_id, nome, descricao: descricao || null, preco: Number(preco),
        validade_dias: validade_dias ? parseInt(validade_dias) : null, servicos: servicosFinal
      }).select().single();
    if (error) throw error;
    res.status(201).json(data);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/pacotes/:id', auth, async (req, res) => {
  if (req.user.perfil !== 'admin') return res.status(403).json({ error: 'Apenas o administrador pode editar pacotes' });
  const { nome, descricao, preco, validade_dias, servicos, ativo } = req.body;
  const updates = {};
  if (nome !== undefined) updates.nome = nome;
  if (descricao !== undefined) updates.descricao = descricao;
  if (preco !== undefined) updates.preco = Number(preco);
  if (validade_dias !== undefined) updates.validade_dias = validade_dias ? parseInt(validade_dias) : null;
  if (servicos !== undefined) updates.servicos = servicos;
  if (ativo !== undefined) updates.ativo = ativo;
  const { data, error } = await supabase.from('pacotes').update(updates)
    .eq('id', req.params.id).eq('salao_id', req.salao_id).select().single();
  if (error || !data) return res.status(404).json({ error: 'Pacote não encontrado' });
  res.json(data);
});

app.delete('/api/pacotes/:id', auth, async (req, res) => {
  if (req.user.perfil !== 'admin') return res.status(403).json({ error: 'Apenas o administrador pode remover pacotes' });
  await supabase.from('pacotes').update({ ativo: false }).eq('id', req.params.id).eq('salao_id', req.salao_id);
  res.json({ message: 'Pacote desativado' });
});

// Vende uma instância de um pacote pra um cliente — cria o saldo de sessões
// disponível e lança a entrada financeira do valor pago pelo pacote.
async function venderPacoteParaCliente({ salaoId, clienteId, pacoteId, valorPago, dataCompra, pagoAgora }) {
  const { data: pacote } = await supabase.from('pacotes')
    .select('*').eq('id', pacoteId).eq('salao_id', salaoId).eq('ativo', true).single();
  if (!pacote) { const e = new Error('Pacote não encontrado'); e.status = 404; throw e; }

  const dataCompraFinal = dataCompra || new Date().toISOString().split('T')[0];
  let validade = null;
  if (pacote.validade_dias) {
    const [ano, mes, dia] = dataCompraFinal.split('-').map(Number);
    validade = new Date(Date.UTC(ano, mes - 1, dia + pacote.validade_dias)).toISOString().split('T')[0];
  }

  const sessoes = (pacote.servicos || []).map(s => ({ servico_id: s.servico_id, qtd_total: s.qtd_sessoes, qtd_usada: 0 }));
  const valorFinal = (valorPago !== undefined && valorPago !== null && valorPago !== '') ? Number(valorPago) : Number(pacote.preco);
  // Por padrão o pacote já entra como pago; se pagoAgora=false, fica marcado
  // como "a receber" (opção de pagar depois).
  const pago = (pagoAgora === undefined || pagoAgora === null) ? true : !!pagoAgora;

  const { data: lancamento } = await supabase.from('lancamentos').insert({
    salao_id: salaoId, cliente_id: clienteId, tipo: 'entrada', categoria: 'Pacote',
    descricao: 'Pacote: ' + pacote.nome, valor: valorFinal, data: dataCompraFinal, pago
  }).select().single();

  const { data: pacoteCliente, error } = await supabase.from('pacotes_clientes')
    .insert({
      salao_id: salaoId, cliente_id: clienteId, pacote_id: pacote.id, nome_snapshot: pacote.nome,
      data_compra: dataCompraFinal, valor_pago: valorFinal, validade, sessoes, status: 'ativo',
      pago, lancamento_id: lancamento ? lancamento.id : null
    }).select().single();
  if (error) throw error;

  return pacoteCliente;
}

// Marca um pacote vendido "pra pagar depois" como pago (quita o lançamento junto)
app.patch('/api/pacotes-clientes/:id/pagar', auth, async (req, res) => {
  if (req.user.perfil !== 'admin') return res.status(403).json({ error: 'Apenas o administrador pode confirmar pagamento de pacotes' });
  try {
    const { data: pc } = await supabase.from('pacotes_clientes')
      .select('id, pago, lancamento_id').eq('id', req.params.id).eq('salao_id', req.salao_id).single();
    if (!pc) return res.status(404).json({ error: 'Pacote do cliente não encontrado' });
    if (pc.pago) return res.status(409).json({ error: 'Este pacote já está marcado como pago' });

    await supabase.from('pacotes_clientes').update({ pago: true }).eq('id', req.params.id);
    if (pc.lancamento_id) {
      await supabase.from('lancamentos').update({ pago: true }).eq('id', pc.lancamento_id);
    }
    res.json({ message: 'Pacote marcado como pago!' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Importa em lote pacotes que os clientes JÁ TINHAM em uso em outro sistema
// (ex.: migrando do Trinks) — diferente do /api/pacotes/lote, que importa
// só o CATÁLOGO. Aqui é "fulano comprou o pacote X, já usou 3 de 10
// sessões, e ainda deve R$ 80" — o estado real de uso e da dívida.
app.post('/api/pacotes-clientes/lote', auth, async (req, res) => {
  if (req.user.perfil !== 'admin') return res.status(403).json({ error: 'Apenas o administrador pode importar pacotes de clientes' });
  const { pacotes } = req.body;
  if (!Array.isArray(pacotes) || !pacotes.length) {
    return res.status(422).json({ error: 'Envie uma lista de pacotes em "pacotes"' });
  }
  if (pacotes.length > 20000) return res.status(422).json({ error: 'Máximo de 20.000 registros por importação' });

  try {
    // Carrega todos os clientes do salão uma vez só, pra casar por nome
    // sem precisar de uma consulta por linha (isso que deixa rápido)
    const { data: todosClientes } = await supabase.from('clientes')
      .select('id, nome').eq('salao_id', req.salao_id).eq('ativo', true);
    const clientePorNome = {};
    (todosClientes || []).forEach(c => { clientePorNome[normalizarTexto(c.nome)] = c.id; });

    let totalInseridos = 0;
    const naoEncontrados = [];

    for (const item of pacotes) {
      const clienteId = clientePorNome[normalizarTexto(item.cliente_nome)];
      if (!clienteId) { naoEncontrados.push(item.cliente_nome); continue; }

      const qtdTotal = Number(item.qtd_total) || 1;
      const qtdUsada = Math.min(Number(item.qtd_usada) || 0, qtdTotal);
      const pago = item.pago !== false;
      const valor = Number(item.valor) || 0;
      const dataCompra = item.data_compra || new Date().toISOString().split('T')[0];

      let lancamentoId = null;
      if (valor > 0) {
        const { data: lanc } = await supabase.from('lancamentos').insert({
          salao_id: req.salao_id, cliente_id: clienteId, tipo: 'entrada', categoria: 'Pacote',
          descricao: 'Pacote (importado): ' + (item.pacote_nome || 'Sem nome'),
          valor, data: dataCompra, pago
        }).select().single();
        lancamentoId = lanc ? lanc.id : null;
      }

      await supabase.from('pacotes_clientes').insert({
        salao_id: req.salao_id, cliente_id: clienteId, pacote_id: null,
        nome_snapshot: item.pacote_nome || 'Pacote importado',
        data_compra: dataCompra, valor_pago: valor, validade: null,
        sessoes: [{ servico_id: null, qtd_total: qtdTotal, qtd_usada: qtdUsada }],
        status: qtdUsada >= qtdTotal ? 'finalizado' : 'ativo',
        pago, lancamento_id: lancamentoId
      });
      totalInseridos++;
    }

    res.status(201).json({
      message: totalInseridos + ' pacote(s) de cliente importado(s)' + (naoEncontrados.length ? ', ' + naoEncontrados.length + ' cliente(s) não encontrado(s)' : '') + '!',
      total: totalInseridos, nao_encontrados: naoEncontrados
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/clientes/:id/pacotes', auth, async (req, res) => {
  if (req.user.perfil !== 'admin') return res.status(403).json({ error: 'Apenas o administrador pode vender pacotes' });
  const { pacote_id, valor_pago, data_compra, pago } = req.body;
  if (!pacote_id) return res.status(422).json({ error: 'pacote_id é obrigatório' });
  try {
    const { data: cliente } = await supabase.from('clientes')
      .select('id').eq('id', req.params.id).eq('salao_id', req.salao_id).single();
    if (!cliente) return res.status(404).json({ error: 'Cliente não encontrado' });

    const pc = await venderPacoteParaCliente({
      salaoId: req.salao_id, clienteId: req.params.id, pacoteId: pacote_id,
      valorPago: valor_pago, dataCompra: data_compra, pagoAgora: pago
    });
    res.status(201).json(pc);
  } catch(e) { res.status(e.status || 500).json({ error: e.message }); }
});

// Lista os pacotes comprados por um cliente, com o saldo de sessões de cada um
app.get('/api/clientes/:id/pacotes', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('pacotes_clientes')
      .select('*').eq('salao_id', req.salao_id).eq('cliente_id', req.params.id)
      .order('data_compra', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════
// CLIENTES
// ═══════════════════════════════════════════════════
app.get('/api/clientes', auth, async (req, res) => {
  const { q, limit = 100, page = 1 } = req.query;
  const offset = (page - 1) * limit;
  let query = supabase.from('clientes').select('*', { count: 'exact' })
    .eq('salao_id', req.salao_id).eq('ativo', true).order('nome').range(offset, offset + Number(limit) - 1);
  if (q) query = query.ilike('nome', `%${q}%`);
  const { data, count, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json({ data: data || [], total: count });
});

// Desativa um cliente (soft delete — preserva o histórico de agendamentos e
// financeiro já existente, só some da lista e não pode mais ser selecionado)
app.delete('/api/clientes/:id', auth, requirePermissao('clientes'), async (req, res) => {
  await supabase.from('clientes').update({ ativo: false })
    .eq('id', req.params.id).eq('salao_id', req.salao_id);
  res.json({ message: 'Cliente desativado' });
});

// Lista clientes inativos (sem agendamento há 60+ dias, ou nunca agendaram)
app.get('/api/clientes/inativos', auth, async (req, res) => {
  const dias = parseInt(req.query.dias) || 60;
  const limite = new Date();
  limite.setDate(limite.getDate() - dias);
  const limiteStr = limite.toISOString().split('T')[0];

  try {
    const { data, error } = await supabase.from('clientes')
      .select('id, nome, telefone, total_gasto, historico_count, ultimo_agendamento, status')
      .eq('salao_id', req.salao_id)
      .or('ultimo_agendamento.lt.' + limiteStr + ',ultimo_agendamento.is.null')
      .neq('status', 'inativo')
      .order('ultimo_agendamento', { ascending: true, nullsFirst: true });
    if (error) throw error;
    res.json(data || []);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/clientes', auth, async (req, res) => {
  const { data, error } = await supabase
    .from('clientes')
    .insert({ ...req.body, salao_id: req.salao_id })
    .select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});

// Importa vários clientes de uma vez (usado pela importação de outro sistema
// — ex.: histórico do Trinks). Uma requisição só, em blocos de 500 no banco,
// em vez de uma requisição por cliente (que seria lento pra centenas deles).
app.post('/api/clientes/lote', auth, async (req, res) => {
  const { clientes } = req.body;
  if (!Array.isArray(clientes) || !clientes.length) {
    return res.status(422).json({ error: 'Envie uma lista de clientes em "clientes"' });
  }
  if (clientes.length > 20000) return res.status(422).json({ error: 'Máximo de 20.000 registros por importação' });

  // Chave de duplicidade: telefone é o identificador mais confiável (nem
  // todo cliente tem e-mail, mas quase todo tem telefone). Cai pra e-mail,
  // depois pro nome, se não tiver telefone.
  function chaveCliente(c) {
    if (c.telefone) return 'tel:' + normalizarTelefone(c.telefone);
    if (c.email) return 'email:' + normalizarTexto(c.email);
    return c.nome ? 'nome:' + normalizarTexto(c.nome) : null;
  }

  const { data: existentes } = await supabase.from('clientes')
    .select('nome, telefone, email').eq('salao_id', req.salao_id);
  const chavesExistentes = new Set((existentes || []).map(chaveCliente).filter(Boolean));
  const { paraInserir, duplicados } = separarDuplicados(clientes, chavesExistentes, chaveCliente);

  if (!paraInserir.length) {
    return res.status(200).json({ message: 'Nenhum cliente novo — todos já existiam ou estavam duplicados na planilha.', total: 0, duplicados });
  }

  const TAMANHO_BLOCO = 500;
  let totalInseridos = 0;
  try {
    for (let i = 0; i < paraInserir.length; i += TAMANHO_BLOCO) {
      const bloco = paraInserir.slice(i, i + TAMANHO_BLOCO).map(c => ({ ...c, salao_id: req.salao_id }));
      const { error } = await supabase.from('clientes').insert(bloco);
      if (error) throw error;
      totalInseridos += bloco.length;
    }
    res.status(201).json({
      message: totalInseridos + ' cliente(s) importado(s)' + (duplicados ? ', ' + duplicados + ' duplicado(s) ignorado(s)' : '') + '!',
      total: totalInseridos, duplicados
    });
  } catch(e) {
    res.status(500).json({ error: 'Erro ao importar em lote (parou em ' + totalInseridos + ' de ' + paraInserir.length + '): ' + e.message });
  }
});

app.put('/api/clientes/:id', auth, async (req, res) => {
  const { data, error } = await supabase
    .from('clientes').update(req.body)
    .eq('id', req.params.id).eq('salao_id', req.salao_id).select().single();
  if (error || !data) return res.status(404).json({ error: 'Não encontrado' });
  res.json(data);
});

// ═══════════════════════════════════════════════════
// AGENDAMENTOS
// ═══════════════════════════════════════════════════
app.get('/api/agendamentos', auth, async (req, res) => {
  const { data, data_inicio, data_fim, status } = req.query;
  let q = supabase.from('agendamentos')
    .select(`id, data_hora, duracao_min, status, valor_total, forma_pgto, observacoes, origem,
             clientes(id, nome, telefone),
             profissionais(id, nome, cor_agenda),
             agendamento_servicos(id, preco, servicos(id, nome, duracao_min))`)
    .eq('salao_id', req.salao_id).order('data_hora');

  // Janela ampliada em UTC para cobrir o dia completo no fuso do Brasil (UTC-3)
  if (data) {
    q = q.gte('data_hora', data + 'T03:00:00+00:00').lte('data_hora', adicionarDia(data) + 'T02:59:59+00:00');
  } else {
    if (data_inicio) q = q.gte('data_hora', data_inicio + 'T03:00:00+00:00');
    if (data_fim)    q = q.lte('data_hora', adicionarDia(data_fim) + 'T02:59:59+00:00');
  }

  // Funcionário vinculado a um profissional só enxerga a própria agenda,
  // mesmo que tente passar outro profissional_id na query string.
  const filtroObrigatorio = profissionalFiltroDoUsuario(req.user);
  if (filtroObrigatorio) {
    q = q.eq('profissional_id', filtroObrigatorio);
  } else if (req.query.profissional_id) {
    q = q.eq('profissional_id', req.query.profissional_id);
  }

  if (status)          q = q.eq('status', status);
  if (req.query.cliente_id) q = q.eq('cliente_id', req.query.cliente_id);

  const { data: rows, error } = await q;
  if (error) return res.status(500).json({ error: error.message });
  res.json(rows || []);
});

// ── AGENDAMENTO RECORRENTE ────────────────────────────
// Soma um intervalo (semanal/quinzenal/mensal) a uma data "YYYY-MM-DD" e
// retorna a próxima data no mesmo formato.
function adicionarIntervaloRecorrencia(dataISO, frequencia) {
  const [ano, mes, dia] = dataISO.split('-').map(Number);
  if (frequencia === 'semanal')   return new Date(Date.UTC(ano, mes - 1, dia + 7)).toISOString().split('T')[0];
  if (frequencia === 'quinzenal') return new Date(Date.UTC(ano, mes - 1, dia + 14)).toISOString().split('T')[0];
  if (frequencia === 'mensal')    return new Date(Date.UTC(ano, mes, dia)).toISOString().split('T')[0];
  throw new Error('Frequência de recorrência inválida');
}

// Gera a lista de datas (strings "YYYY-MM-DD") de uma recorrência, começando
// na data base (inclusive) até a data final (inclusive), com um teto de
// segurança de 52 ocorrências pra nunca gerar uma série absurdamente longa.
function gerarDatasRecorrencia(dataInicialISO, frequencia, dataFimISO) {
  const MAX_OCORRENCIAS = 52;
  const datas = [dataInicialISO];
  let atual = dataInicialISO;
  while (datas.length < MAX_OCORRENCIAS) {
    const proxima = adicionarIntervaloRecorrencia(atual, frequencia);
    if (proxima > dataFimISO) break; // comparação lexicográfica funciona em "YYYY-MM-DD"
    datas.push(proxima);
    atual = proxima;
  }
  return datas;
}

// Cria UM agendamento (usado tanto pelo fluxo normal quanto por cada ocorrência
// de uma recorrência). Faz checagem de conflito de horário e, se livre, insere
// o agendamento + os serviços vinculados + o lançamento financeiro pendente.
// Retorna { status: 'criado', agendamento } ou { status: 'conflito', data_hora }.
async function criarAgendamentoUnico({
  salaoId, clienteId, profissionalId, dataHora, servicosInfo,
  profComissaoPct, observacoes, origem, recorrenciaId, pacotePorServico
}) {
  pacotePorServico = pacotePorServico || {}; // { [servico_id]: pacote_cliente_id } — serviços pagos via pacote

  const duracao_total = servicosInfo.reduce((s, sv) => s + sv.duracao_min, 0);
  // Só cobra agora os serviços que NÃO vieram de um pacote já pago antes —
  // e usa o preço EFETIVO daquele dia da semana (se o serviço tiver preço
  // diferente configurado pra esse dia; senão usa o preço padrão)
  const valor_total = servicosInfo.reduce((s, sv) => s + (pacotePorServico[sv.id] ? 0 : precoEfetivoServico(sv, dataHora)), 0);

  const data_hora_final = /[+-]\d{2}:\d{2}$|Z$/.test(dataHora) ? dataHora : dataHora + '-03:00';
  const dataParte = data_hora_final.split('T')[0];
  const inicioDia = dataParte + 'T03:00:00+00:00';
  const fimDia     = adicionarDia(dataParte) + 'T02:59:59+00:00';

  const { data: existentes } = await supabase.from('agendamentos')
    .select('id, data_hora, duracao_min')
    .eq('salao_id', salaoId).eq('profissional_id', profissionalId)
    .gte('data_hora', inicioDia).lte('data_hora', fimDia)
    .neq('status', 'cancelado');

  const novoInicioMin = utcParaMinutosBrasil(new Date(data_hora_final).toISOString());
  const novoFimMin    = novoInicioMin + duracao_total;

  const conflito = (existentes || []).find(function(ag) {
    var agInicio = utcParaMinutosBrasil(ag.data_hora);
    var agFim = agInicio + (ag.duracao_min || 60);
    return (novoInicioMin < agFim && novoFimMin > agInicio);
  });

  if (conflito) return { status: 'conflito', data_hora: data_hora_final };

  const insertPayload = {
    salao_id: salaoId, cliente_id: clienteId, profissional_id: profissionalId,
    data_hora: data_hora_final, duracao_min: duracao_total, valor_total,
    origem: origem || 'backoffice', observacoes
  };
  if (recorrenciaId) insertPayload.recorrencia_id = recorrenciaId;

  const { data: ag, error } = await supabase.from('agendamentos')
    .insert(insertPayload).select().single();
  if (error) throw error;

  // A comissão é calculada sobre o preço CHEIO do serviço naquele dia (que
  // já reflete o preço específico do dia da semana, se houver) — o
  // profissional continua recebendo normalmente mesmo quando o cliente já
  // pagou pelo pacote antes. Só a cobrança do cliente (lançamento) é que
  // não se repete.
  const linhas = servicosInfo.map(sv => {
    const precoDoServicoNesseDia = precoEfetivoServico(sv, dataHora);
    const cpct = sv.comissao_pct ?? profComissaoPct ?? 40;
    const pacoteClienteId = pacotePorServico[sv.id] || null;
    return {
      agendamento_id: ag.id, servico_id: sv.id, preco: precoDoServicoNesseDia,
      comissao_pct: cpct, comissao_valor: (precoDoServicoNesseDia * cpct) / 100,
      pago_via_pacote: !!pacoteClienteId, pacote_cliente_id: pacoteClienteId
    };
  });
  if (linhas.length) await supabase.from('agendamento_servicos').insert(linhas);

  // Só lança cobrança financeira se sobrou algo pra cobrar do cliente agora
  if (valor_total > 0) {
    await supabase.from('lancamentos').insert({
      salao_id: salaoId, agendamento_id: ag.id, cliente_id: clienteId, tipo: 'entrada',
      categoria: 'Serviço', descricao: 'Agendamento #' + ag.id.slice(-6).toUpperCase(),
      valor: valor_total, data: dataParte, pago: false
    });
  }

  return { status: 'criado', agendamento: ag };
}

app.post('/api/agendamentos', auth, async (req, res) => {
  const { cliente_id, profissional_id, data_hora, servicos, observacoes, origem, recorrencia,
          vender_pacote, pacotes_utilizados } = req.body;
  if (!cliente_id || !profissional_id || !data_hora || !servicos || !servicos.length) {
    return res.status(422).json({ error: 'Dados incompletos' });
  }

  // Funcionário vinculado só pode criar agendamento para o próprio profissional
  const filtroObrigatorio = profissionalFiltroDoUsuario(req.user);
  if (filtroObrigatorio && filtroObrigatorio !== profissional_id) {
    return res.status(403).json({ error: 'Você só pode criar agendamentos para sua própria agenda' });
  }

  // Valida a recorrência, se enviada
  const dataBaseISO = data_hora.split('T')[0];
  const horaParte = data_hora.split('T')[1] || '09:00:00';
  let datasRecorrencia = null;
  if (recorrencia && recorrencia.ate) {
    const frequenciasValidas = ['semanal', 'quinzenal', 'mensal'];
    if (!frequenciasValidas.includes(recorrencia.frequencia)) {
      return res.status(422).json({ error: 'Frequência de recorrência inválida (use semanal, quinzenal ou mensal)' });
    }
    if (recorrencia.ate < dataBaseISO) {
      return res.status(422).json({ error: 'A data final da recorrência deve ser depois da data do primeiro agendamento' });
    }
    datasRecorrencia = gerarDatasRecorrencia(dataBaseISO, recorrencia.frequencia, recorrencia.ate);
  }

  // Pacotes (venda na hora e/ou consumo de sessão existente) só valem pra
  // agendamento único — mantém a recorrência simples e previsível
  if (datasRecorrencia && (vender_pacote || (pacotes_utilizados && pacotes_utilizados.length))) {
    return res.status(422).json({ error: 'Pacotes não podem ser combinados com agendamento recorrente' });
  }

  try {
    const { data: srvcs } = await supabase
      .from('servicos').select('id, nome, preco, duracao_min, comissao_pct, precos_por_dia')
      .in('id', servicos).eq('salao_id', req.salao_id);

    const { data: prof } = await supabase
      .from('profissionais').select('comissao_pct, nome, email').eq('id', profissional_id).single();

    const { data: clienteInfo } = await supabase
      .from('clientes').select('nome').eq('id', cliente_id).single();
    const nomesServicos = (srvcs || []).map(s => s.nome).filter(Boolean);

    // ── Sem recorrência: comportamento normal, um único agendamento ──
    if (!datasRecorrencia) {
      // Vende um pacote novo na hora, se pedido (modelo Trinks: oferecer o
      // pacote enquanto agenda). Se falhar, aborta antes de criar o agendamento.
      if (vender_pacote && vender_pacote.pacote_id) {
        await venderPacoteParaCliente({
          salaoId: req.salao_id, clienteId: cliente_id, pacoteId: vender_pacote.pacote_id,
          valorPago: vender_pacote.valor_pago, dataCompra: dataBaseISO, pagoAgora: vender_pacote.pago
        });
      }

      // Valida e resolve o consumo de sessões de pacotes já existentes
      const pacotePorServico = {};
      const consumosParaAplicar = []; // aplicados só depois que o agendamento for criado com sucesso
      if (pacotes_utilizados && pacotes_utilizados.length) {
        for (const uso of pacotes_utilizados) {
          if (!servicos.includes(uso.servico_id)) {
            return res.status(422).json({ error: 'Serviço do pacote não faz parte dos serviços selecionados no agendamento' });
          }
          const { data: pc } = await supabase.from('pacotes_clientes')
            .select('*').eq('id', uso.pacote_cliente_id).eq('salao_id', req.salao_id).eq('cliente_id', cliente_id).single();
          if (!pc) return res.status(404).json({ error: 'Pacote do cliente não encontrado' });
          if (pc.status !== 'ativo') return res.status(422).json({ error: 'Este pacote não está mais ativo' });
          if (pc.validade && pc.validade < dataBaseISO) return res.status(422).json({ error: 'Este pacote está vencido' });

          const sessoes = pc.sessoes || [];
          const linha = sessoes.find(s => s.servico_id === uso.servico_id);
          if (!linha || linha.qtd_usada >= linha.qtd_total) {
            return res.status(422).json({ error: 'Este pacote não tem mais sessões disponíveis para o serviço selecionado' });
          }

          pacotePorServico[uso.servico_id] = pc.id;
          consumosParaAplicar.push({ pacoteCliente: pc, servicoId: uso.servico_id });
        }
      }

      const resultado = await criarAgendamentoUnico({
        salaoId: req.salao_id, clienteId: cliente_id, profissionalId: profissional_id,
        dataHora: data_hora, servicosInfo: srvcs || [], profComissaoPct: prof?.comissao_pct,
        observacoes, origem, pacotePorServico
      });
      if (resultado.status === 'conflito') {
        return res.status(409).json({ error: 'Este profissional já tem um agendamento nesse horário. Escolha outro horário ou profissional.' });
      }

      // Agendamento criado com sucesso — agora sim debita as sessões usadas
      for (const consumo of consumosParaAplicar) {
        const sessoesAtualizadas = (consumo.pacoteCliente.sessoes || []).map(s =>
          s.servico_id === consumo.servicoId ? { ...s, qtd_usada: s.qtd_usada + 1 } : s
        );
        const todasEsgotadas = sessoesAtualizadas.every(s => s.qtd_usada >= s.qtd_total);
        await supabase.from('pacotes_clientes').update({
          sessoes: sessoesAtualizadas,
          status: todasEsgotadas ? 'finalizado' : 'ativo'
        }).eq('id', consumo.pacoteCliente.id);
      }

      // Notificação por e-mail pro profissional — best-effort (não atrasa nem
      // quebra a resposta se o envio falhar). A função nunca rejeita a
      // Promise (sempre resolve com {enviado,motivo}), então checamos o
      // resultado explicitamente pra deixar rastro no log se falhar —
      // um .catch() sozinho aqui nunca pegaria nada.
      if (prof && prof.email) {
        notificarProfissionalNovoAgendamento(
          prof.email, prof.nome, clienteInfo?.nome || 'Cliente',
          data_hora, nomesServicos, resultado.agendamento.valor_total
        ).then(r => {
          if (!r.enviado) console.error('Notificação de agendamento NÃO enviada pro profissional ' + prof.email + ': ' + r.motivo);
        }).catch(e => console.error('Erro inesperado ao notificar profissional:', e.message));
      } else {
        console.log('Profissional ' + profissional_id + ' sem e-mail cadastrado — notificação de agendamento não enviada.');
      }

      return res.status(201).json(resultado.agendamento);
    }

    // ── Com recorrência: cria uma ocorrência por data, pulando conflitos ──
    const recorrenciaId = crypto.randomUUID();
    const criados = [];
    const pulados = [];
    for (const dataISO of datasRecorrencia) {
      const dataHoraCompleta = dataISO + 'T' + horaParte;
      const resultado = await criarAgendamentoUnico({
        salaoId: req.salao_id, clienteId: cliente_id, profissionalId: profissional_id,
        dataHora: dataHoraCompleta, servicosInfo: srvcs || [], profComissaoPct: prof?.comissao_pct,
        observacoes, origem, recorrenciaId
      });
      if (resultado.status === 'criado') criados.push(resultado.agendamento);
      else pulados.push(resultado.data_hora);
    }

    if (!criados.length) {
      return res.status(409).json({ error: 'Nenhum agendamento pôde ser criado — todos os horários da recorrência já estão ocupados.' });
    }

    // Notificação por e-mail pro profissional — best-effort, um único e-mail
    // resumindo a série inteira (evita spam de vários e-mails separados)
    if (prof && prof.email) {
      notificarProfissionalRecorrencia(prof.email, prof.nome, clienteInfo?.nome || 'Cliente', criados, nomesServicos)
        .then(r => {
          if (!r.enviado) console.error('Notificação de recorrência NÃO enviada pro profissional ' + prof.email + ': ' + r.motivo);
        }).catch(e => console.error('Erro inesperado ao notificar profissional (recorrência):', e.message));
    } else {
      console.log('Profissional ' + profissional_id + ' sem e-mail cadastrado — notificação de recorrência não enviada.');
    }

    res.status(201).json({
      recorrencia_id: recorrenciaId,
      total_criados: criados.length,
      total_pulados: pulados.length,
      criados, pulados
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch('/api/agendamentos/:id/status', auth, async (req, res) => {
  const { status, forma_pgto, pago } = req.body;
  const updates = { status };
  if (forma_pgto) updates.forma_pgto = forma_pgto;

  let query = supabase.from('agendamentos').update(updates)
    .eq('id', req.params.id).eq('salao_id', req.salao_id);

  // Funcionário vinculado só pode alterar status de agendamentos da própria agenda
  const filtroObrigatorio = profissionalFiltroDoUsuario(req.user);
  if (filtroObrigatorio) query = query.eq('profissional_id', filtroObrigatorio);

  const { data, error } = await query.select().single();
  if (error || !data) return res.status(404).json({ error: 'Não encontrado' });

  let whatsapp_link = null;
  let infoTaxaMaquininha = { taxa_total: 0, taxa_profissional: 0 };

  if (status === 'concluido') {
    // Desconto opcional aplicado na hora de concluir — desconta tanto do
    // valor cobrado quanto proporcionalmente da comissão do profissional
    // (decisão de negócio: o profissional também sente o desconto, não só
    // o salão).
    const desconto = Number(req.body.desconto || 0);
    if (desconto > 0) {
      const valorOriginal = Number(data.valor_total || 0);
      if (desconto > valorOriginal) {
        return res.status(422).json({ error: 'O desconto não pode ser maior que o valor do atendimento (' + valorOriginal + ')' });
      }
      const valorFinal = Number((valorOriginal - desconto).toFixed(2));
      const fatorDesconto = valorOriginal > 0 ? valorFinal / valorOriginal : 1;

      await supabase.from('agendamentos')
        .update({ valor_total: valorFinal, desconto_aplicado: desconto })
        .eq('id', req.params.id);
      // Atualiza a cópia local também, pro resto da função (taxa de
      // maquininha, lançamento financeiro, resposta) já usar o valor certo
      data.valor_total = valorFinal;
      data.desconto_aplicado = desconto;

      const { data: servicosDoAgendamento } = await supabase
        .from('agendamento_servicos').select('*').eq('agendamento_id', req.params.id);
      for (const linha of (servicosDoAgendamento || [])) {
        await supabase.from('agendamento_servicos').update({
          preco: Number((Number(linha.preco) * fatorDesconto).toFixed(2)),
          comissao_valor: Number((Number(linha.comissao_valor) * fatorDesconto).toFixed(2))
        }).eq('id', linha.id);
      }
    }

    // Ficou combinado de pagar depois (fiado) — não marca como pago e não
    // aplica taxa de maquininha (não teve cartão nenhum passado ainda).
    // O padrão continua sendo "pago", pra não mudar o comportamento de
    // quem não mandar esse campo.
    const marcarComoPago = pago !== false;

    // Atualiza lancamento — já reflete o valor com desconto (se algum foi aplicado)
    await supabase.from('lancamentos')
      .update({ pago: marcarComoPago, forma_pgto, valor: data.valor_total }).eq('agendamento_id', req.params.id);

    // Aplica o desconto da taxa da maquininha na comissão do profissional
    // (só se o pagamento foi no cartão, o salão configurou uma taxa, E o
    // atendimento já foi realmente pago agora — fiado não paga taxa ainda)
    if (marcarComoPago) {
      try {
        infoTaxaMaquininha = await aplicarTaxaMaquininha(
          req.params.id, req.salao_id, Number(data.valor_total || 0), forma_pgto
        );
      } catch(e) { console.error('Erro ao aplicar taxa maquininha:', e.message); }
    }

    // Atualiza estatísticas do cliente automaticamente
    if (data.cliente_id) {
      try {
        // Conta total de visitas e soma total gasto
        const { data: ags } = await supabase
          .from('agendamentos')
          .select('valor_total')
          .eq('cliente_id', data.cliente_id)
          .eq('salao_id', req.salao_id)
          .eq('status', 'concluido');

        const total_visitas = ags ? ags.length : 0;
        const total_gasto   = ags ? ags.reduce((s, a) => s + Number(a.valor_total || 0), 0) : 0;

        // Define status baseado em visitas
        let novo_status = 'ativo';
        if (total_visitas >= 10) novo_status = 'vip';
        else if (total_visitas === 1) novo_status = 'novo';

        await supabase.from('clientes').update({
          historico_count: total_visitas,
          total_gasto: total_gasto,
          ultimo_agendamento: new Date().toISOString().split('T')[0],
          status: novo_status
        }).eq('id', data.cliente_id).eq('salao_id', req.salao_id);
      } catch(e) { console.error('Erro ao atualizar stats cliente:', e.message); }
    }

    // Gera link de WhatsApp para pedir avaliação e convidar retorno
    try {
      const { data: cliente } = await supabase.from('clientes')
        .select('nome, telefone').eq('id', data.cliente_id).single();
      const { data: salao } = await supabase.from('saloes')
        .select('nome').eq('id', req.salao_id).single();

      if (cliente && cliente.telefone) {
        const telLimpo = cliente.telefone.replace(/\D/g, '');
        const telComPais = telLimpo.length === 11 ? '55' + telLimpo : telLimpo;
        const linkAgendar = 'https://belezaprooficial.com.br/agendar.html?salao=' + req.salao_id;
        const msg = 'Oi ' + cliente.nome.split(' ')[0] + '! Foi um prazer te atender hoje na ' +
          (salao?.nome || 'nossa loja') + '. Como foi sua experiência? ' +
          'Quando quiser marcar seu próximo horário, é só acessar: ' + linkAgendar;
        whatsapp_link = 'https://wa.me/' + telComPais + '?text=' + encodeURIComponent(msg);
      }
    } catch(e) { console.error('Erro ao gerar link WhatsApp:', e.message); }
  }

  res.json({ ...data, whatsapp_link, taxa_maquininha: infoTaxaMaquininha });
});

// ═══════════════════════════════════════════════════
// DASHBOARD
// ═══════════════════════════════════════════════════
app.get('/api/dashboard/kpis', auth, async (req, res) => {
  const hoje = dataAtualBrasil();
  const inicioMes = hoje.slice(0, 7) + '-01';

  const filtroObrigatorio = profissionalFiltroDoUsuario(req.user);

  let qAgHoje = supabase.from('agendamentos').select('id', { count: 'exact' })
    .eq('salao_id', req.salao_id)
    .gte('data_hora', hoje + 'T03:00:00+00:00').lte('data_hora', adicionarDia(hoje) + 'T02:59:59+00:00')
    .not('status', 'in', '("cancelado","nao_compareceu")');
  if (filtroObrigatorio) qAgHoje = qAgHoje.eq('profissional_id', filtroObrigatorio);

  const [{ count: agHoje }, { data: lancHoje }, { count: clientes }, { data: novos }] = await Promise.all([
    qAgHoje,
    supabase.from('lancamentos').select('tipo, valor')
      .eq('salao_id', req.salao_id).eq('data', hoje).eq('pago', true),
    supabase.from('clientes').select('id', { count: 'exact' })
      .eq('salao_id', req.salao_id).eq('ativo', true),
    supabase.from('clientes').select('id')
      .eq('salao_id', req.salao_id).gte('created_at', inicioMes + 'T03:00:00+00:00'),
  ]);
  const faturamento = (lancHoje || [])
    .filter(l => l.tipo === 'entrada').reduce((s, l) => s + Number(l.valor), 0);
  res.json({ agendamentos_hoje: agHoje || 0, faturamento_hoje: faturamento,
             clientes_ativos: clientes || 0, novos_clientes_mes: novos?.length || 0 });
});

app.get('/api/dashboard/agenda-hoje', auth, async (req, res) => {
  const hoje = dataAtualBrasil();
  let q = supabase.from('agendamentos')
    .select(`id, data_hora, status, valor_total,
             clientes(nome, telefone), profissionais(nome, cor_agenda),
             agendamento_servicos(servicos(nome))`)
    .eq('salao_id', req.salao_id)
    .gte('data_hora', hoje + 'T03:00:00+00:00').lte('data_hora', adicionarDia(hoje) + 'T02:59:59+00:00')
    .not('status', 'eq', 'cancelado').order('data_hora');

  const filtroObrigatorio = profissionalFiltroDoUsuario(req.user);
  if (filtroObrigatorio) q = q.eq('profissional_id', filtroObrigatorio);

  const { data } = await q;
  res.json(data || []);
});

app.get('/api/dashboard/top-servicos', auth, async (req, res) => {
  const inicioMes = dataAtualBrasil().slice(0, 7) + '-01';
  let q = supabase.from('agendamento_servicos')
    .select('servicos(nome), preco, agendamentos!inner(data_hora, salao_id, status, profissional_id)')
    .eq('agendamentos.salao_id', req.salao_id)
    .eq('agendamentos.status', 'concluido')
    .gte('agendamentos.data_hora', inicioMes + 'T03:00:00+00:00');

  const filtroObrigatorio = profissionalFiltroDoUsuario(req.user);
  if (filtroObrigatorio) q = q.eq('agendamentos.profissional_id', filtroObrigatorio);

  const { data } = await q;
  const map = {};
  (data || []).forEach(row => {
    const nome = row.servicos?.nome || 'Desconhecido';
    if (!map[nome]) map[nome] = { nome, count: 0, total: 0 };
    map[nome].count++;
    map[nome].total += Number(row.preco);
  });
  res.json(Object.values(map).sort((a, b) => b.total - a.total).slice(0, 8));
});

// ═══════════════════════════════════════════════════
// FINANCEIRO
// ═══════════════════════════════════════════════════
app.get('/api/financeiro/resumo', auth, requirePermissao('financeiro'), async (req, res) => {
  const hoje = new Date();
  const y = hoje.getFullYear(), m = hoje.getMonth() + 1;
  const inicio = `${y}-${String(m).padStart(2,'0')}-01`;
  const fim = new Date(y, m, 0).toISOString().split('T')[0];
  const { data } = await supabase.from('lancamentos').select('tipo, valor, pago')
    .eq('salao_id', req.salao_id).gte('data', inicio).lte('data', fim);
  const receita = (data || []).filter(l => l.tipo === 'entrada').reduce((s, l) => s + Number(l.valor), 0);
  const despesa = (data || []).filter(l => l.tipo === 'saida').reduce((s, l) => s + Number(l.valor), 0);
  const apagar  = (data || []).filter(l => l.tipo === 'entrada' && !l.pago).reduce((s, l) => s + Number(l.valor), 0);
  res.json({ receita, despesa, lucro: receita - despesa, apagar });
});

// ── FIADO / CONTAS A RECEBER ──────────────────────────
// Agrupa por cliente todos os lançamentos de entrada ainda não pagos —
// "quem me deve e quanto". Só considera lançamentos com cliente_id (os
// vindos de agendamento/pacote têm; um "+Lançamento" manual sem cliente
// selecionado não entra aqui, porque não tem como saber de quem é).
app.get('/api/financeiro/fiado', auth, requirePermissao('financeiro'), async (req, res) => {
  try {
    const { data: pendentes, error } = await supabase.from('lancamentos')
      .select('id, cliente_id, valor, data, descricao, categoria')
      .eq('salao_id', req.salao_id).eq('tipo', 'entrada').eq('pago', false)
      .not('cliente_id', 'is', null);
    if (error) throw error;

    if (!pendentes || !pendentes.length) return res.json([]);

    const idsClientes = [...new Set(pendentes.map(l => l.cliente_id))];
    const { data: clientesInfo } = await supabase.from('clientes')
      .select('id, nome, telefone').in('id', idsClientes);
    const clientesPorId = {};
    (clientesInfo || []).forEach(c => { clientesPorId[c.id] = c; });

    const porCliente = {};
    pendentes.forEach(l => {
      if (!porCliente[l.cliente_id]) {
        const c = clientesPorId[l.cliente_id] || { nome: 'Cliente removido', telefone: '' };
        porCliente[l.cliente_id] = {
          cliente_id: l.cliente_id, nome: c.nome, telefone: c.telefone,
          total_devido: 0, quantidade_lancamentos: 0, data_mais_antiga: l.data, itens: []
        };
      }
      const registro = porCliente[l.cliente_id];
      registro.total_devido += Number(l.valor);
      registro.quantidade_lancamentos += 1;
      if (l.data < registro.data_mais_antiga) registro.data_mais_antiga = l.data;
      registro.itens.push({ id: l.id, valor: l.valor, data: l.data, descricao: l.descricao, categoria: l.categoria });
    });

    const lista = Object.values(porCliente).sort((a, b) => b.total_devido - a.total_devido);
    res.json(lista);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Mesmo relatório, mas devolvendo um CSV pronto pra baixar/abrir no Excel
// Registra um pagamento (total ou parcial) de um lançamento em aberto — se
// pagar menos que o valor total, "quebra" o lançamento em dois: um já pago
// (o valor que entrou agora) e outro que continua pendente com o restante.
// Assim o relatório de Fiado sempre reflete o saldo real que ainda falta.
app.post('/api/financeiro/lancamentos/:id/pagar', auth, requirePermissao('financeiro'), async (req, res) => {
  const { valor, forma_pgto } = req.body;
  try {
    const { data: lanc } = await supabase.from('lancamentos')
      .select('*').eq('id', req.params.id).eq('salao_id', req.salao_id).single();
    if (!lanc) return res.status(404).json({ error: 'Lançamento não encontrado' });
    if (lanc.pago) return res.status(409).json({ error: 'Esse lançamento já está pago' });

    const valorPago = (valor !== undefined && valor !== null && valor !== '')
      ? Number(valor) : Number(lanc.valor);
    if (!valorPago || valorPago <= 0) return res.status(422).json({ error: 'Informe um valor válido' });
    if (valorPago > Number(lanc.valor) + 0.01) {
      return res.status(422).json({ error: 'O valor pago não pode ser maior que o valor devido (' + lanc.valor + ')' });
    }

    const restante = Number((Number(lanc.valor) - valorPago).toFixed(2));
    const pagouTudo = restante <= 0.01;

    if (pagouTudo) {
      // Pagou o valor inteiro — só marca como pago, sem precisar quebrar em dois
      const { data } = await supabase.from('lancamentos')
        .update({ pago: true, forma_pgto: forma_pgto || lanc.forma_pgto }).eq('id', lanc.id).select().single();
      return res.json({ pago_total: true, lancamento: data });
    }

    // Pagamento parcial: cria um novo lançamento com o valor pago agora
    // (já quitado) e reduz o lançamento original pro saldo que ainda falta
    const { data: pagamento } = await supabase.from('lancamentos').insert({
      salao_id: req.salao_id, cliente_id: lanc.cliente_id, tipo: lanc.tipo, categoria: lanc.categoria,
      descricao: lanc.descricao + ' (pagamento parcial)', valor: valorPago,
      data: new Date().toISOString().split('T')[0], forma_pgto: forma_pgto || null, pago: true,
      agendamento_id: lanc.agendamento_id || null
    }).select().single();

    const { data: atualizado } = await supabase.from('lancamentos')
      .update({ valor: restante }).eq('id', lanc.id).select().single();

    res.json({ pago_total: false, restante, pagamento, lancamento: atualizado });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/financeiro/fiado/exportar', auth, requirePermissao('financeiro'), async (req, res) => {
  try {
    const { data: pendentes, error } = await supabase.from('lancamentos')
      .select('cliente_id, valor, data, descricao')
      .eq('salao_id', req.salao_id).eq('tipo', 'entrada').eq('pago', false)
      .not('cliente_id', 'is', null);
    if (error) throw error;

    const idsClientes = [...new Set((pendentes || []).map(l => l.cliente_id))];
    const { data: clientesInfo } = await supabase.from('clientes')
      .select('id, nome, telefone').in('id', idsClientes.length ? idsClientes : ['-']);
    const clientesPorId = {};
    (clientesInfo || []).forEach(c => { clientesPorId[c.id] = c; });

    const porCliente = {};
    (pendentes || []).forEach(l => {
      if (!porCliente[l.cliente_id]) {
        const c = clientesPorId[l.cliente_id] || { nome: 'Cliente removido', telefone: '' };
        porCliente[l.cliente_id] = { nome: c.nome, telefone: c.telefone || '', total: 0, qtd: 0, maisAntiga: l.data };
      }
      porCliente[l.cliente_id].total += Number(l.valor);
      porCliente[l.cliente_id].qtd += 1;
      if (l.data < porCliente[l.cliente_id].maisAntiga) porCliente[l.cliente_id].maisAntiga = l.data;
    });

    const linhas = Object.values(porCliente).sort((a, b) => b.total - a.total);
    const cabecalho = 'Cliente;Telefone;Total Devido;Quantidade de Cobrancas;Pendente Desde\n';
    const corpo = linhas.map(l =>
      [l.nome, l.telefone, l.total.toFixed(2).replace('.', ','), l.qtd, l.maisAntiga].join(';')
    ).join('\n');

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="fiado.csv"');
    res.send('\uFEFF' + cabecalho + corpo); // BOM na frente pra acentuação abrir certo no Excel
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/financeiro/lancamentos', auth, requirePermissao('financeiro'), async (req, res) => {
  const { tipo, limit = 50, page = 1 } = req.query;
  const offset = (page - 1) * limit;
  let q = supabase.from('lancamentos').select('*', { count: 'exact' })
    .eq('salao_id', req.salao_id).order('data', { ascending: false })
    .range(offset, offset + Number(limit) - 1);
  if (tipo) q = q.eq('tipo', tipo);
  const { data, count, error } = await q;
  if (error) return res.status(500).json({ error: error.message });
  res.json({ data: data || [], total: count });
});

app.post('/api/financeiro/lancamentos', auth, requirePermissao('financeiro'), async (req, res) => {
  const { data, error } = await supabase
    .from('lancamentos').insert({ ...req.body, salao_id: req.salao_id }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});

// Insere vários lançamentos de uma vez (usado pela importação de dados de
// outros sistemas — ex.: histórico de vendas/despesas com milhares de
// linhas). Uma requisição só, em vez de uma por linha, e o banco recebe em
// blocos de 500 pra não estourar o tamanho de uma única inserção.
app.post('/api/financeiro/lancamentos/lote', auth, requirePermissao('financeiro'), async (req, res) => {
  const { lancamentos } = req.body;
  if (!Array.isArray(lancamentos) || !lancamentos.length) {
    return res.status(422).json({ error: 'Envie uma lista de lançamentos em "lancamentos"' });
  }
  if (lancamentos.length > 20000) {
    return res.status(422).json({ error: 'Máximo de 20.000 lançamentos por importação' });
  }

  // Normaliza cada linha primeiro (mesma transformação que ia direto pro
  // insert antes), pra calcular a chave de duplicidade sobre os valores
  // finais — evita "R$ 55,00" e "55" contarem como coisas diferentes.
  const normalizados = lancamentos.map(l => ({
    tipo: l.tipo === 'saida' ? 'saida' : 'entrada',
    categoria: l.categoria || 'Outros',
    descricao: l.descricao || '',
    valor: Number(l.valor) || 0,
    data: l.data,
    pago: l.pago !== false
  }));

  // Chave: mesma data + categoria + descrição + valor = provavelmente o
  // mesmo lançamento (protege contra importar a mesma planilha 2 vezes)
  function chaveLancamento(l) {
    return [l.tipo, normalizarTexto(l.categoria), normalizarTexto(l.descricao), l.valor, l.data].join('|');
  }

  const { data: existentes } = await supabase.from('lancamentos')
    .select('tipo, categoria, descricao, valor, data').eq('salao_id', req.salao_id);
  const chavesExistentes = new Set((existentes || []).map(chaveLancamento));
  const { paraInserir, duplicados } = separarDuplicados(normalizados, chavesExistentes, chaveLancamento);

  if (!paraInserir.length) {
    return res.status(200).json({ message: 'Nenhum lançamento novo — todos já existiam ou estavam duplicados na planilha.', total: 0, duplicados });
  }

  const TAMANHO_BLOCO = 500;
  let totalInseridos = 0;
  try {
    for (let i = 0; i < paraInserir.length; i += TAMANHO_BLOCO) {
      const bloco = paraInserir.slice(i, i + TAMANHO_BLOCO).map(l => ({ ...l, salao_id: req.salao_id }));
      const { error } = await supabase.from('lancamentos').insert(bloco);
      if (error) throw error;
      totalInseridos += bloco.length;
    }
    res.status(201).json({
      message: totalInseridos + ' lançamento(s) importado(s)' + (duplicados ? ', ' + duplicados + ' duplicado(s) ignorado(s)' : '') + '!',
      total: totalInseridos, duplicados
    });
  } catch(e) {
    res.status(500).json({ error: 'Erro ao importar em lote (parou em ' + totalInseridos + ' de ' + paraInserir.length + '): ' + e.message });
  }
});

// Marca um lançamento como pago ou não pago
app.patch('/api/financeiro/lancamentos/:id', auth, requirePermissao('financeiro'), async (req, res) => {
  const { pago, forma_pgto } = req.body;
  const updates = {};
  if (typeof pago === 'boolean') updates.pago = pago;
  if (forma_pgto) updates.forma_pgto = forma_pgto;
  const { data, error } = await supabase
    .from('lancamentos').update(updates)
    .eq('id', req.params.id).eq('salao_id', req.salao_id)
    .select().single();
  if (error || !data) return res.status(404).json({ error: 'Lançamento não encontrado' });
  res.json(data);
});

// ═══════════════════════════════════════════════════
// ESTOQUE
// ═══════════════════════════════════════════════════
app.get('/api/estoque', auth, requirePermissao('estoque'), async (req, res) => {
  const { q } = req.query;
  let query = supabase.from('produtos').select('*')
    .eq('salao_id', req.salao_id).eq('ativo', true).order('nome');
  if (q) query = query.ilike('nome', `%${q}%`);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data || []);
});

app.get('/api/estoque/alertas', auth, requirePermissao('estoque'), async (req, res) => {
  const { data } = await supabase.from('produtos').select('id, nome, qtd_atual, qtd_minima, categoria')
    .eq('salao_id', req.salao_id).eq('ativo', true);
  const alertas = (data || []).filter(p => Number(p.qtd_atual) < Number(p.qtd_minima));
  res.json(alertas);
});

app.post('/api/estoque', auth, requirePermissao('estoque'), async (req, res) => {
  const { data, error } = await supabase
    .from('produtos').insert({ ...req.body, salao_id: req.salao_id }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});

// Importa vários produtos de uma vez (importação de outro sistema)
app.post('/api/estoque/lote', auth, requirePermissao('estoque'), async (req, res) => {
  const { produtos } = req.body;
  if (!Array.isArray(produtos) || !produtos.length) {
    return res.status(422).json({ error: 'Envie uma lista de produtos em "produtos"' });
  }
  if (produtos.length > 20000) return res.status(422).json({ error: 'Máximo de 20.000 registros por importação' });

  function chaveProduto(p) { return p.nome ? 'nome:' + normalizarTexto(p.nome) : null; }

  const { data: existentes } = await supabase.from('produtos')
    .select('nome').eq('salao_id', req.salao_id).eq('ativo', true);
  const chavesExistentes = new Set((existentes || []).map(chaveProduto).filter(Boolean));
  const { paraInserir, duplicados } = separarDuplicados(produtos, chavesExistentes, chaveProduto);

  if (!paraInserir.length) {
    return res.status(200).json({ message: 'Nenhum produto novo — todos já existiam ou estavam duplicados na planilha.', total: 0, duplicados });
  }

  const TAMANHO_BLOCO = 500;
  let totalInseridos = 0;
  try {
    for (let i = 0; i < paraInserir.length; i += TAMANHO_BLOCO) {
      const bloco = paraInserir.slice(i, i + TAMANHO_BLOCO).map(p => ({ ...p, salao_id: req.salao_id }));
      const { error } = await supabase.from('produtos').insert(bloco);
      if (error) throw error;
      totalInseridos += bloco.length;
    }
    res.status(201).json({
      message: totalInseridos + ' produto(s) importado(s)' + (duplicados ? ', ' + duplicados + ' duplicado(s) ignorado(s)' : '') + '!',
      total: totalInseridos, duplicados
    });
  } catch(e) {
    res.status(500).json({ error: 'Erro ao importar em lote (parou em ' + totalInseridos + ' de ' + paraInserir.length + '): ' + e.message });
  }
});

app.put('/api/estoque/:id', auth, requirePermissao('estoque'), async (req, res) => {
  const { data, error } = await supabase.from('produtos').update(req.body)
    .eq('id', req.params.id).eq('salao_id', req.salao_id).select().single();
  if (error || !data) return res.status(404).json({ error: 'Não encontrado' });
  res.json(data);
});

// Desativa um produto (soft delete — mantém o histórico de movimentação e
// de compras parceladas antigas que apontam pra ele)
app.delete('/api/estoque/:id', auth, requirePermissao('estoque'), async (req, res) => {
  await supabase.from('produtos').update({ ativo: false })
    .eq('id', req.params.id).eq('salao_id', req.salao_id);
  res.json({ message: 'Produto desativado' });
});

// Movimentar estoque (reposição manual / ajuste avulso)
app.post('/api/estoque/:id/movimentar', auth, requirePermissao('estoque'), async (req, res) => {
  const { tipo, quantidade, motivo } = req.body;
  const { data: prod } = await supabase.from('produtos')
    .select('qtd_atual, nome').eq('id', req.params.id).eq('salao_id', req.salao_id).single();
  if (!prod) return res.status(404).json({ error: 'Produto não encontrado' });
  const delta = tipo === 'entrada' ? Number(quantidade) : -Number(quantidade);
  const nova  = Number(prod.qtd_atual) + delta;
  if (nova < 0) return res.status(422).json({ error: 'Estoque insuficiente. Atual: ' + prod.qtd_atual });
  await supabase.from('produtos').update({ qtd_atual: nova }).eq('id', req.params.id);
  await supabase.from('movimentacoes_estoque').insert({
    salao_id: req.salao_id, produto_id: req.params.id,
    tipo, quantidade, motivo, usuario_id: req.user.id
  });
  res.json({ nova_quantidade: nova, produto: prod.nome });
});

// Registra CONSUMO de um produto durante um atendimento (ex.: shampoo usado
// no cliente) — desconta do estoque, mas NÃO gera receita nenhuma, só
// histórico de quem usou quanto (pedido específico: rastrear consumo por
// profissional, tipo Jairo usando shampoo nos clientes dele).
app.post('/api/estoque/:id/consumir', auth, requirePermissao('estoque'), async (req, res) => {
  const { profissional_id, quantidade, cliente_id, motivo } = req.body;
  if (!profissional_id || !quantidade || Number(quantidade) <= 0) {
    return res.status(422).json({ error: 'profissional_id e quantidade (maior que zero) são obrigatórios' });
  }
  const { data: prod } = await supabase.from('produtos')
    .select('qtd_atual, nome').eq('id', req.params.id).eq('salao_id', req.salao_id).single();
  if (!prod) return res.status(404).json({ error: 'Produto não encontrado' });

  const nova = Number(prod.qtd_atual) - Number(quantidade);
  if (nova < 0) return res.status(422).json({ error: 'Estoque insuficiente. Atual: ' + prod.qtd_atual });

  await supabase.from('produtos').update({ qtd_atual: nova }).eq('id', req.params.id);
  await supabase.from('movimentacoes_estoque').insert({
    salao_id: req.salao_id, produto_id: req.params.id, tipo: 'consumo',
    quantidade, motivo: motivo || null, profissional_id, cliente_id: cliente_id || null,
    usuario_id: req.user.id
  });
  res.json({ nova_quantidade: nova, produto: prod.nome });
});

// Registra a VENDA de um produto pro cliente (ex.: vendeu um shampoo pra
// ele levar pra casa) — desconta do estoque E gera um lançamento financeiro
// de verdade, vinculado ao cliente (entra no relatório de Fiado se marcado
// como pendente).
app.post('/api/estoque/:id/vender', auth, requirePermissao('estoque'), async (req, res) => {
  const { cliente_id, profissional_id, quantidade, valor, forma_pgto, pago, data } = req.body;
  if (!cliente_id || !quantidade || Number(quantidade) <= 0) {
    return res.status(422).json({ error: 'cliente_id e quantidade (maior que zero) são obrigatórios' });
  }
  const { data: prod } = await supabase.from('produtos')
    .select('qtd_atual, nome, preco_venda').eq('id', req.params.id).eq('salao_id', req.salao_id).single();
  if (!prod) return res.status(404).json({ error: 'Produto não encontrado' });

  const nova = Number(prod.qtd_atual) - Number(quantidade);
  if (nova < 0) return res.status(422).json({ error: 'Estoque insuficiente. Atual: ' + prod.qtd_atual });

  const valorFinal = (valor !== undefined && valor !== null && valor !== '')
    ? Number(valor) : Number(prod.preco_venda || 0) * Number(quantidade);
  const dataFinal = data || new Date().toISOString().split('T')[0];
  const pagoFinal = pago !== false;

  await supabase.from('produtos').update({ qtd_atual: nova }).eq('id', req.params.id);

  const { data: lancamento } = await supabase.from('lancamentos').insert({
    salao_id: req.salao_id, cliente_id, tipo: 'entrada', categoria: 'Produto',
    descricao: 'Venda: ' + prod.nome + ' (' + quantidade + 'x)',
    valor: valorFinal, data: dataFinal, forma_pgto, pago: pagoFinal
  }).select().single();

  await supabase.from('movimentacoes_estoque').insert({
    salao_id: req.salao_id, produto_id: req.params.id, tipo: 'venda',
    quantidade, valor: valorFinal, cliente_id, profissional_id: profissional_id || null,
    usuario_id: req.user.id, lancamento_id: lancamento ? lancamento.id : null
  });

  res.json({ nova_quantidade: nova, produto: prod.nome, valor: valorFinal, lancamento_id: lancamento ? lancamento.id : null });
});

// Histórico de movimentação de estoque — quem deu baixa em quê e quando.
// Filtros opcionais: produto_id, profissional_id, tipo, data_inicio, data_fim.
app.get('/api/estoque/movimentacoes', auth, requirePermissao('estoque'), async (req, res) => {
  const { produto_id, profissional_id, tipo, data_inicio, data_fim, limit = 100 } = req.query;
  try {
    let q = supabase.from('movimentacoes_estoque').select('*')
      .eq('salao_id', req.salao_id).order('created_at', { ascending: false }).limit(Number(limit));
    if (produto_id) q = q.eq('produto_id', produto_id);
    if (profissional_id) q = q.eq('profissional_id', profissional_id);
    if (tipo) q = q.eq('tipo', tipo);
    if (data_inicio) q = q.gte('created_at', data_inicio);
    if (data_fim) q = q.lte('created_at', data_fim + 'T23:59:59');
    const { data: movs, error } = await q;
    if (error) throw error;
    if (!movs || !movs.length) return res.json([]);

    // Busca os nomes de produto/profissional/cliente/usuário separado (evita
    // depender de relacionamento embutido do Supabase, que já deu problema
    // antes com "mais de um relacionamento" quando há FK múltipla)
    const idsProdutos = [...new Set(movs.map(m => m.produto_id).filter(Boolean))];
    const idsProfissionais = [...new Set(movs.map(m => m.profissional_id).filter(Boolean))];
    const idsClientes = [...new Set(movs.map(m => m.cliente_id).filter(Boolean))];
    const idsUsuarios = [...new Set(movs.map(m => m.usuario_id).filter(Boolean))];

    const [produtosInfo, profissionaisInfo, clientesInfo, usuariosInfo] = await Promise.all([
      idsProdutos.length ? supabase.from('produtos').select('id, nome').in('id', idsProdutos) : { data: [] },
      idsProfissionais.length ? supabase.from('profissionais').select('id, nome').in('id', idsProfissionais) : { data: [] },
      idsClientes.length ? supabase.from('clientes').select('id, nome').in('id', idsClientes) : { data: [] },
      idsUsuarios.length ? supabase.from('usuarios').select('id, nome').in('id', idsUsuarios) : { data: [] },
    ]);
    const nomePorId = (lista) => { const m = {}; (lista.data || []).forEach(x => { m[x.id] = x.nome; }); return m; };
    const produtoNome = nomePorId(produtosInfo), profNome = nomePorId(profissionaisInfo),
          cliNome = nomePorId(clientesInfo), userNome = nomePorId(usuariosInfo);

    res.json(movs.map(m => ({
      ...m,
      produto_nome: produtoNome[m.produto_id] || '—',
      profissional_nome: profNome[m.profissional_id] || null,
      cliente_nome: cliNome[m.cliente_id] || null,
      usuario_nome: userNome[m.usuario_id] || null
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════
// COMISSÕES
// ═══════════════════════════════════════════════════
app.get('/api/comissoes', auth, requirePermissao('comissoes'), async (req, res) => {
  let { data: profissionais } = await supabase.from('profissionais')
    .select('id, nome, comissao_pct, cor_agenda').eq('salao_id', req.salao_id).eq('ativo', true);
  if (!profissionais) return res.json([]);

  // Funcionário vinculado a um profissional só enxerga a própria comissão
  const filtroObrigatorio = profissionalFiltroDoUsuario(req.user);
  if (filtroObrigatorio) {
    profissionais = profissionais.filter(p => p.id === filtroObrigatorio);
  }

  // Aceita ?mes=2026-06 para navegar entre meses; padrão é o mês atual
  let ano, mesNum;
  if (req.query.mes && /^\d{4}-\d{2}$/.test(req.query.mes)) {
    [ano, mesNum] = req.query.mes.split('-').map(Number);
  } else {
    const now = new Date();
    ano = now.getFullYear();
    mesNum = now.getMonth() + 1;
  }
  const ini = `${ano}-${String(mesNum).padStart(2,'0')}-01`;
  const fim = new Date(ano, mesNum, 0).toISOString().split('T')[0];

  const resultado = await Promise.all(profissionais.map(async p => {
    // Verifica se este período já foi fechado/pago para este profissional
    const { data: fechamento } = await supabase.from('fechamentos_comissao')
      .select('id, status, pago_em, total_comissao, total_bruto, total_servicos')
      .eq('salao_id', req.salao_id)
      .eq('profissional_id', p.id).eq('periodo_inicio', ini).maybeSingle();

    // Soma as parcelas de compras parceladas ainda pendentes desse profissional
    // (ex: produto que ele comprou parcelado) — pra ficar visível na hora de
    // fechar a comissão que existe um desconto a combinar.
    const { data: comprasDoProfissional } = await supabase.from('compras_profissional')
      .select('parcelas_compra_profissional(valor, status)')
      .eq('salao_id', req.salao_id).eq('profissional_id', p.id);
    const compras_pendentes_total = (comprasDoProfissional || []).reduce((soma, compra) => {
      const pendentesDaCompra = (compra.parcelas_compra_profissional || [])
        .filter(parcela => parcela.status === 'pendente')
        .reduce((s, parcela) => s + Number(parcela.valor || 0), 0);
      return soma + pendentesDaCompra;
    }, 0);

    // Se já está pago, mostra zerado (já foi quitado, não soma de novo)
    if (fechamento && fechamento.status === 'pago') {
      return { ...p, total_servicos: 0, total_bruto: 0, total_comissao: 0, fechamento, compras_pendentes_total };
    }

    // Senão, calcula normalmente a partir dos agendamentos concluídos
    const { data: svcs } = await supabase.from('agendamento_servicos')
      .select('preco, comissao_valor, agendamentos!inner(data_hora, status, profissional_id)')
      .eq('agendamentos.profissional_id', p.id)
      .eq('agendamentos.status', 'concluido')
      .gte('agendamentos.data_hora', ini + 'T03:00:00+00:00')
      .lte('agendamentos.data_hora', adicionarDia(fim) + 'T02:59:59+00:00');
    const total_bruto    = (svcs || []).reduce((s, sv) => s + Number(sv.preco || 0), 0);
    const total_comissao = (svcs || []).reduce((s, sv) => s + Number(sv.comissao_valor || 0), 0);
    return { ...p, total_servicos: svcs?.length || 0, total_bruto, total_comissao, fechamento, compras_pendentes_total };
  }));
  res.json(resultado);
});

// Verifica se o usuário pode fechar/reabrir comissões — admin sempre pode;
// usuário custom só pode se tiver a permissão extra 'fechar_comissao' marcada
// (é uma ação sensível de dinheiro, separada da simples permissão de ver 'comissoes').
async function podeFecharComissao(user) {
  if (user.perfil === 'admin') return true;
  const { data: perm } = await supabase.from('usuario_permissoes')
    .select('permissoes').eq('usuario_id', user.id).maybeSingle();
  const permissoes = (perm && perm.permissoes) || [];
  return permissoes.includes('fechar_comissao');
}

app.post('/api/comissoes/fechar', auth, async (req, res) => {
  const { profissional_id, periodo_inicio, periodo_fim } = req.body;

  if (!(await podeFecharComissao(req.user))) {
    return res.status(403).json({ error: 'Você não tem permissão para fechar comissões' });
  }

  const now = new Date();
  const ini = periodo_inicio || `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-01`;
  const fim = periodo_fim    || new Date(now.getFullYear(), now.getMonth()+1, 0).toISOString().split('T')[0];

  try {
    // Calcula os totais reais a partir dos agendamentos concluídos do período
    // (não confia em valor mandado pelo frontend — sempre recalcula no servidor)
    const { data: svcs } = await supabase.from('agendamento_servicos')
      .select('preco, comissao_valor, agendamentos!inner(data_hora, status, profissional_id)')
      .eq('agendamentos.profissional_id', profissional_id)
      .eq('agendamentos.status', 'concluido')
      .gte('agendamentos.data_hora', ini + 'T03:00:00+00:00')
      .lte('agendamentos.data_hora', adicionarDia(fim) + 'T02:59:59+00:00');

    const total_servicos = svcs?.length || 0;
    const total_bruto     = (svcs || []).reduce((s, sv) => s + Number(sv.preco || 0), 0);
    const total_comissao  = (svcs || []).reduce((s, sv) => s + Number(sv.comissao_valor || 0), 0);

    if (total_servicos === 0) {
      return res.status(400).json({ error: 'Nenhum serviço concluído neste período para fechar.' });
    }

    // Verifica se já existe fechamento para este período
    const { data: existing } = await supabase.from('fechamentos_comissao')
      .select('id, status').eq('salao_id', req.salao_id)
      .eq('profissional_id', profissional_id).eq('periodo_inicio', ini).maybeSingle();

    if (existing && existing.status === 'pago') {
      return res.status(409).json({ error: 'Este período já foi fechado e pago anteriormente.' });
    }

    let data, error;
    if (existing) {
      // Atualiza o existente
      ({ data, error } = await supabase.from('fechamentos_comissao')
        .update({
          total_comissao, total_bruto, total_servicos,
          status: 'pago', pago_em: new Date(), periodo_fim: fim
        })
        .eq('id', existing.id).select().single());
    } else {
      // Insere novo
      ({ data, error } = await supabase.from('fechamentos_comissao')
        .insert({
          salao_id: req.salao_id, profissional_id, periodo_inicio: ini, periodo_fim: fim,
          total_comissao, total_bruto, total_servicos,
          status: 'pago', pago_em: new Date()
        })
        .select().single());
    }
    if (error) throw error;

    // Notificação por e-mail pro profissional — best-effort. A função nunca
    // rejeita a Promise (sempre resolve com {enviado,motivo}), então checa
    // o resultado explicitamente em vez de um .catch() sozinho.
    const { data: profInfo } = await supabase.from('profissionais')
      .select('nome, email').eq('id', profissional_id).single();
    if (profInfo && profInfo.email) {
      notificarProfissionalComissaoFechada(profInfo.email, profInfo.nome, total_comissao, ini, fim)
        .then(r => {
          if (!r.enviado) console.error('Notificação de comissão fechada NÃO enviada pro profissional ' + profInfo.email + ': ' + r.motivo);
        }).catch(e => console.error('Erro inesperado ao notificar profissional (comissão):', e.message));
    }

    res.json(data);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Reabre um fechamento de comissão pago por engano (volta a calcular normalmente)
app.delete('/api/comissoes/fechamento/:id', auth, async (req, res) => {
  if (!(await podeFecharComissao(req.user))) {
    return res.status(403).json({ error: 'Você não tem permissão para reabrir fechamentos de comissão' });
  }
  try {
    const { error } = await supabase.from('fechamentos_comissao')
      .delete().eq('id', req.params.id).eq('salao_id', req.salao_id);
    if (error) throw error;
    res.json({ message: 'Fechamento removido, comissão volta a ser calculada normalmente.' });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ═══════════════════════════════════════════════════
// SALÃO
// ═══════════════════════════════════════════════════
// Criar usuário recepcionista / profissional
app.post('/api/usuarios', auth, async (req, res) => {
  // Só admin pode criar usuários
  if (req.user.perfil !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
  const { nome, cargo, email, senha, perfil, permissoes, profissional_id } = req.body;
  if (!nome || !email || !senha) return res.status(422).json({ error: 'Nome, email e senha obrigatórios' });
  if (String(senha).length < 6) return res.status(422).json({ error: 'Senha deve ter pelo menos 6 caracteres' });
  if (!emailValido(email)) return res.status(422).json({ error: 'Informe um e-mail válido' });

  const perfil_final = perfil === 'admin' ? 'admin' : 'custom';
  const permissoes_final = perfil_final === 'admin'
    ? ['dashboard','agenda','clientes','financeiro','estoque','comissoes','profissionais','servicos','pacotes','config']
    : (permissoes || ['dashboard','agenda','clientes','estoque','comissoes']);

  try {
    const { data: existe } = await supabase.from('usuarios').select('id').eq('email', email).single();
    if (existe) return res.status(409).json({ error: 'Email já cadastrado' });

    // Se veio profissional_id, valida que pertence a este salão
    let profissional_id_final = null;
    if (perfil_final === 'custom' && profissional_id) {
      const { data: prof } = await supabase.from('profissionais')
        .select('id, email').eq('id', profissional_id).eq('salao_id', req.salao_id).single();
      if (!prof) return res.status(422).json({ error: 'Profissional inválido para este salão' });
      profissional_id_final = prof.id;

      // Preenche automaticamente o e-mail do profissional com o e-mail de
      // login, se ele ainda não tiver um e-mail próprio — evita a confusão
      // de "vinculei o usuário mas o profissional continua sem e-mail" (são
      // dois campos separados: o de login e o de notificação).
      if (!prof.email) {
        await supabase.from('profissionais').update({ email }).eq('id', prof.id);
      }
    }

    const senha_hash = await bcrypt.hash(senha, 12);
    const codigoVerificacao = gerarCodigoVerificacao();
    const { data, error } = await supabase.from('usuarios')
      .insert({
        salao_id: req.salao_id, nome, email, senha_hash, perfil: perfil_final,
        profissional_id: profissional_id_final, email_verificado: false,
        codigo_verificacao: codigoVerificacao, codigo_verificacao_expira: expiracaoCodigoVerificacao()
      })
      .select('id, nome, email, perfil, profissional_id, email_verificado').single();
    if (error) throw error;

    // Espera o resultado real do envio, pra devolver pro admin se deu certo ou não
    const resultadoEmail = await enviarCodigoVerificacao(email, nome, codigoVerificacao)
      .catch(e => ({ enviado: false, motivo: e.message }));

    // Salva permissões customizadas
    try {
      await supabase.from('usuario_permissoes').upsert({
        usuario_id: data.id, salao_id: req.salao_id, permissoes: permissoes_final
      }, { onConflict: 'usuario_id' });
    } catch(permErr) { console.log('Permissoes nao salvas:', permErr.message); }

    res.status(201).json({
      ...data, permissoes: permissoes_final,
      email_enviado: resultadoEmail.enviado,
      email_motivo_falha: resultadoEmail.enviado ? null : resultadoEmail.motivo
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Listar usuários do salão
app.get('/api/usuarios', auth, async (req, res) => {
  if (req.user.perfil !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
  try {
    const { data: usuarios, error } = await supabase.from('usuarios')
      .select('id, nome, email, perfil, ativo, ultimo_login, profissional_id, email_verificado')
      .eq('salao_id', req.salao_id).order('nome');
    if (error) throw error;

    // Busca as permissões separadamente (sem depender de relação/FK declarada
    // entre usuarios e usuario_permissoes — mais seguro e à prova de schema)
    const ids = (usuarios || []).map(u => u.id);
    let permissoesPorUsuario = {};
    if (ids.length) {
      const { data: permsRows } = await supabase.from('usuario_permissoes')
        .select('usuario_id, permissoes').in('usuario_id', ids);
      (permsRows || []).forEach(p => { permissoesPorUsuario[p.usuario_id] = p.permissoes; });
    }

    // Busca os nomes dos profissionais vinculados também separadamente —
    // o embed automático (usuarios -> profissionais) falha quando o banco
    // tem mais de uma relação possível entre essas duas tabelas.
    const profissionalIds = [...new Set((usuarios || []).map(u => u.profissional_id).filter(Boolean))];
    let nomePorProfissional = {};
    if (profissionalIds.length) {
      const { data: profsRows } = await supabase.from('profissionais')
        .select('id, nome').in('id', profissionalIds);
      (profsRows || []).forEach(p => { nomePorProfissional[p.id] = p.nome; });
    }

    const TODAS_PERMISSOES_ADMIN = ['dashboard','agenda','clientes','financeiro','estoque','comissoes','profissionais','servicos','pacotes','config','fechar_comissao'];
    const comPermissoes = (usuarios || []).map(u => ({
      ...u,
      profissionais: (u.profissional_id && nomePorProfissional[u.profissional_id]) ? { nome: nomePorProfissional[u.profissional_id] } : null,
      permissoes: u.perfil === 'admin' ? TODAS_PERMISSOES_ADMIN : (permissoesPorUsuario[u.id] || [])
    }));
    res.json(comPermissoes);
  } catch(e) {
    console.error('Erro ao listar usuarios:', e.message);
    res.status(500).json({ error: 'Erro ao carregar usuários: ' + e.message });
  }
});

// Editar permissões (e vínculo com profissional) do usuário
app.put('/api/usuarios/:id/permissoes', auth, async (req, res) => {
  if (req.user.perfil !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
  const { permissoes, profissional_id } = req.body;
  if (!permissoes || !permissoes.length) return res.status(422).json({ error: 'Permissoes obrigatorias' });

  try {
    // Valida que o usuário-alvo pertence a este salão
    const { data: alvo } = await supabase.from('usuarios')
      .select('id, perfil, email').eq('id', req.params.id).eq('salao_id', req.salao_id).single();
    if (!alvo) return res.status(404).json({ error: 'Usuário não encontrado' });

    let profissional_id_final = null;
    if (alvo.perfil !== 'admin' && profissional_id) {
      const { data: prof } = await supabase.from('profissionais')
        .select('id, email').eq('id', profissional_id).eq('salao_id', req.salao_id).single();
      if (!prof) return res.status(422).json({ error: 'Profissional inválido para este salão' });
      profissional_id_final = prof.id;

      // Mesmo preenchimento automático do e-mail do profissional, agora pro
      // caso de vincular um usuário já existente (não só na criação)
      if (!prof.email) {
        await supabase.from('profissionais').update({ email: alvo.email }).eq('id', prof.id);
      }
    }

    const { error } = await supabase.from('usuario_permissoes').upsert({
      usuario_id: req.params.id, salao_id: req.salao_id, permissoes
    }, { onConflict: 'usuario_id' });
    if (error) throw error;

    await supabase.from('usuarios')
      .update({ profissional_id: profissional_id_final })
      .eq('id', req.params.id).eq('salao_id', req.salao_id);

    res.json({ message: 'Permissoes atualizadas', permissoes, profissional_id: profissional_id_final });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Deletar/desativar usuário
app.delete('/api/usuarios/:id', auth, async (req, res) => {
  if (req.user.perfil !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'Não pode deletar a si mesmo' });
  await supabase.from('usuarios').update({ ativo: false }).eq('id', req.params.id).eq('salao_id', req.salao_id);
  res.json({ message: 'Usuário desativado' });
});

// (proteção real de financeiro/estoque/profissionais/serviços já é feita
// rota a rota via requirePermissao(), acima)


// Envia um e-mail de teste pro endereço informado — forma rápida de
// confirmar se o Resend está configurado certo, sem precisar criar usuário
// de teste nem esperar um agendamento/comissão de verdade.
app.post('/api/admin/testar-email', auth, async (req, res) => {
  if (req.user.perfil !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
  const { email } = req.body;
  if (!email || !emailValido(email)) return res.status(422).json({ error: 'Informe um e-mail válido' });

  const resultado = await enviarEmailSimples(
    email,
    '✅ Teste de e-mail — Beleza Pro',
    'Se você está lendo isso, o envio de e-mail do seu sistema Beleza Pro está funcionando! 🎉\n\nEste é só um teste, não precisa fazer nada.\n\n— Beleza Pro'
  );

  if (!resultado.enviado) {
    return res.status(502).json({ error: 'Falha ao enviar: ' + resultado.motivo });
  }
  res.json({ message: 'E-mail de teste enviado! Confira a caixa de entrada (e o spam) de ' + email });
});

app.get('/api/saloes/meu', auth, async (req, res) => {
  const { data, error } = await supabase.from('saloes')
    .select('*, planos(nome, features)').eq('id', req.salao_id).single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data || {});
});

app.put('/api/saloes/meu', auth, async (req, res) => {
  const { nome, telefone, whatsapp, email, endereco, cidade, estado, configuracoes } = req.body;
  const updates = { nome, telefone, whatsapp, email, endereco, cidade, estado };
  if (configuracoes) {
    // Faz merge com as configurações existentes em vez de substituir tudo —
    // evita que salvar o horário de funcionamento apague a taxa da maquininha
    // (ou vice-versa), já que ambos vivem dentro da mesma coluna JSONB.
    try {
      const { data: atual } = await supabase.from('saloes')
        .select('configuracoes').eq('id', req.salao_id).single();
      updates.configuracoes = { ...(atual?.configuracoes || {}), ...configuracoes };
    } catch(e) {
      updates.configuracoes = configuracoes;
    }
  }
  const { data, error } = await supabase.from('saloes')
    .update(updates)
    .eq('id', req.salao_id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ═══════════════════════════════════════════════════
// MERCADO PAGO
// ═══════════════════════════════════════════════════
const MP_TOKEN = process.env.MP_ACCESS_TOKEN || '';

app.post('/api/pagamento/criar', auth, async (req, res) => {
  if (!MP_TOKEN) return res.status(500).json({ error: 'Mercado Pago nao configurado' });
  try {
    // Busca dados do salao
    const { data: salao } = await supabase.from('saloes')
      .select('nome').eq('id', req.salao_id).single();
    const { data: usuario } = await supabase.from('usuarios')
      .select('nome, email').eq('id', req.user.id).single();

    // Cria preferencia de pagamento (Checkout Pro - aceita cartao, PIX, boleto)
    const response = await fetch('https://api.mercadopago.com/checkout/preferences', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + MP_TOKEN },
      body: JSON.stringify({
        items: [{
          title: 'Beleza Pro - Plano Mensal',
          description: 'Acesso completo ao sistema de gestao para saloes - ' + (salao?.nome || ''),
          quantity: 1,
          currency_id: 'BRL',
          unit_price: 59.90
        }],
        payer: {
          name: usuario?.nome || '',
          email: usuario?.email || ''
        },
        payment_methods: {
          excluded_payment_types: [],
          installments: 1
        },
        back_urls: {
          success: 'https://belezaprooficial.com.br/painel.html?pago=1',
          failure: 'https://belezaprooficial.com.br/painel.html?pago=0',
          pending: 'https://belezaprooficial.com.br/painel.html?pago=2'
        },
        auto_return: 'approved',
        statement_descriptor: 'BELEZA PRO',
        external_reference: req.salao_id
      })
    });
    const preference = await response.json();
    if (!response.ok) throw new Error(preference.message || 'Erro ao criar pagamento');
    res.json({ link: preference.init_point, id: preference.id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/pagamento/webhook', async (req, res) => {
  const { type, data } = req.body;
  try {
    if ((type === 'payment' || type === 'payment.updated' || type === 'payment.created') && data?.id) {
      // Busca detalhes do pagamento
      const r = await fetch('https://api.mercadopago.com/v1/payments/' + data.id, {
        headers: { 'Authorization': 'Bearer ' + MP_TOKEN }
      });
      const pgto = await r.json();

      // Se aprovado, renova acesso do salao por 30 dias
      if (pgto.status === 'approved' && pgto.external_reference) {
        const salao_id = pgto.external_reference;
        const prox = new Date();
        prox.setDate(prox.getDate() + 30);
        await supabase.from('saloes')
          .update({ ativo: true, trial_ate: prox })
          .eq('id', salao_id);

        // Registra lancamento financeiro (para controle interno)
        await supabase.from('lancamentos').insert({
          salao_id: salao_id,
          tipo: 'entrada',
          categoria: 'Assinatura',
          descricao: 'Mensalidade Beleza Pro - ' + new Date().toLocaleDateString('pt-BR'),
          valor: pgto.transaction_amount || 59.90,
          data: new Date().toISOString().split('T')[0],
          forma_pgto: pgto.payment_type_id || 'mercado_pago',
          pago: true
        }).catch(() => {}); // ignora erro se tabela nao existir
      }
    }
  } catch(e) { console.error('Webhook erro:', e.message); }
  res.sendStatus(200);
});

app.get('/api/pagamento/status', auth, async (req, res) => {
  const { data: salao } = await supabase.from('saloes').select('trial_ate, ativo').eq('id', req.salao_id).single();

  // Calcula dias considerando fim do dia da data de vencimento
  let dias = 0;
  if (salao?.trial_ate) {
    const trial = new Date(salao.trial_ate);
    // Ajusta para fim do dia (23:59:59) para não cortar antes da hora
    trial.setHours(23, 59, 59, 999);
    const hoje = new Date();
    dias = Math.ceil((trial - hoje) / 86400000);
  }

  res.json({
    ativo: salao?.ativo,
    em_trial: dias > 0,
    dias_restantes: Math.max(0, dias),
    trial_expirado: dias <= 0,
    trial_ate: salao?.trial_ate
  });
});

// ═══════════════════════════════════════════════════
// AGENDAMENTO PÚBLICO (sem autenticação)
// ═══════════════════════════════════════════════════

// Busca dados públicos do salão (nome, logo)
app.get('/api/publico/salao/:slug', async (req, res) => {
  try {
    const { data, error } = await supabase.from('saloes')
      .select('id, nome, telefone, endereco, cidade').eq('id', req.params.slug).single();
    if (error || !data) return res.status(404).json({ error: 'Salão não encontrado' });
    res.json(data);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Lista serviços ativos do salão (público)
app.get('/api/publico/servicos/:salaoId', async (req, res) => {
  try {
    const { data, error } = await supabase.from('servicos')
      .select('id, nome, categoria, duracao_min, preco')
      .eq('salao_id', req.params.salaoId).eq('ativo', true).order('nome');
    if (error) throw error;
    res.json(data || []);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Lista profissionais ativos do salão (público)
app.get('/api/publico/profissionais/:salaoId', async (req, res) => {
  try {
    const { data, error } = await supabase.from('profissionais')
      .select('id, nome, especialidade, cor_agenda')
      .eq('salao_id', req.params.salaoId).eq('ativo', true).order('nome');
    if (error) throw error;
    res.json(data || []);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Busca horários disponíveis para um profissional em uma data
app.get('/api/publico/horarios/:salaoId', async (req, res) => {
  const { profissional_id, data, duracao_min } = req.query;
  if (!profissional_id || !data) return res.status(422).json({ error: 'profissional_id e data obrigatórios' });

  try {
    // Busca horário de funcionamento configurado (padrão 08:00-19:00 se não definido)
    const { data: salao } = await supabase.from('saloes')
      .select('configuracoes').eq('id', req.params.salaoId).single();
    const horaAbreCfg  = salao?.configuracoes?.horario_abre  || '08:00';
    const horaFechaCfg = salao?.configuracoes?.horario_fecha || '19:00';
    const [horaAbre]  = horaAbreCfg.split(':').map(Number);
    const [horaFecha] = horaFechaCfg.split(':').map(Number);

    // Verifica se o salão funciona nesse dia da semana (padrão: todos os dias)
    const diasFechado = salao?.configuracoes?.dias_fechado || []; // ex: [0] = domingo fechado
    const diaSemana = new Date(data + 'T12:00:00').getDay();
    if (diasFechado.includes(diaSemana)) {
      return res.json({ horarios: [], fechado: true });
    }

    // Busca agendamentos já marcados nesse dia para esse profissional
    // Janela ampliada em UTC para cobrir o dia completo no fuso do Brasil (UTC-3)
    const inicioDia = data + 'T03:00:00+00:00';
    const fimDia     = adicionarDia(data) + 'T02:59:59+00:00';
    const { data: ocupados } = await supabase.from('agendamentos')
      .select('data_hora, duracao_min')
      .eq('salao_id', req.params.salaoId)
      .eq('profissional_id', profissional_id)
      .gte('data_hora', inicioDia)
      .lte('data_hora', fimDia)
      .neq('status', 'cancelado');

    // Converte ocupados para minutos do dia [inicio, fim]
    const ocupadosMin = (ocupados || []).map(function(ag) {
      var inicioMin = utcParaMinutosBrasil(ag.data_hora);
      var fimMin = inicioMin + (ag.duracao_min || 60);
      return [inicioMin, fimMin];
    });

    // Gera slots de horário dentro do funcionamento configurado, intervalos de 30min
    const slots = [];
    const dur = parseInt(duracao_min) || 60;
    for (let h = horaAbre; h < horaFecha; h++) {
      for (let m = 0; m < 60; m += 30) {
        const inicioMin = h * 60 + m;
        const fimMin = inicioMin + dur;
        if (fimMin > horaFecha * 60) continue; // não passa do horário de fechamento

        const conflito = ocupadosMin.some(function(o) {
          return (inicioMin < o[1] && fimMin > o[0]);
        });

        if (!conflito) {
          const hh = String(h).padStart(2,'0');
          const mm = String(m).padStart(2,'0');
          slots.push(hh + ':' + mm);
        }
      }
    }

    // Remove horários passados se for hoje
    const hojeBrasil = dataAtualBrasil();
    let slotsDisponiveis = slots;
    if (data === hojeBrasil) {
      const horaAtual = minutosAgoraBrasil();
      slotsDisponiveis = slots.filter(function(s) {
        const parts = s.split(':').map(Number);
        return (parts[0] * 60 + parts[1]) > horaAtual + 30;
      });
    }

    res.json({ horarios: slotsDisponiveis });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Cria agendamento público (cliente final)
app.post('/api/publico/agendar/:salaoId', async (req, res) => {
  const { nome, telefone, servico_id, profissional_id, data, hora_inicio } = req.body;
  if (!nome || !telefone || !servico_id || !profissional_id || !data || !hora_inicio) {
    return res.status(422).json({ error: 'Todos os campos são obrigatórios' });
  }

  try {
    const salao_id = req.params.salaoId;

    // Busca dados do serviço
    const { data: servico } = await supabase.from('servicos')
      .select('id, nome, duracao_min, preco, comissao_pct, precos_por_dia').eq('id', servico_id).single();
    if (!servico) return res.status(404).json({ error: 'Serviço não encontrado' });

    const data_hora = data + 'T' + hora_inicio + ':00-03:00';
    // Preço EFETIVO daquele dia da semana (usa o preço especial configurado
    // pro dia, se houver; senão o preço padrão do serviço)
    const precoEfetivo = precoEfetivoServico(servico, data_hora);

    // Busca ou cria cliente pelo telefone
    let { data: cliente } = await supabase.from('clientes')
      .select('id').eq('salao_id', salao_id).eq('telefone', telefone).maybeSingle();

    if (!cliente) {
      const { data: novoCliente, error: cliErr } = await supabase.from('clientes')
        .insert({ salao_id, nome, telefone, status: 'novo' })
        .select('id').single();
      if (cliErr) throw cliErr;
      cliente = novoCliente;
    }

    // Verifica conflito de horário (segurança)
    const [h, m] = hora_inicio.split(':').map(Number);
    const inicioMin = h * 60 + m;
    const fimMin = inicioMin + servico.duracao_min;
    const inicioDia = data + 'T03:00:00+00:00';
    const fimDia     = adicionarDia(data) + 'T02:59:59+00:00';

    const { data: existentes } = await supabase.from('agendamentos')
      .select('data_hora, duracao_min')
      .eq('salao_id', salao_id).eq('profissional_id', profissional_id)
      .gte('data_hora', inicioDia).lte('data_hora', fimDia)
      .neq('status', 'cancelado');

    const temConflito = (existentes || []).some(function(ag) {
      var agInicio = utcParaMinutosBrasil(ag.data_hora);
      var agFim = agInicio + (ag.duracao_min || 60);
      return (inicioMin < agFim && fimMin > agInicio);
    });

    if (temConflito) {
      return res.status(409).json({ error: 'Este horário já foi reservado. Escolha outro.' });
    }

    // Busca comissão do profissional (fallback) — e nome/e-mail pra notificação
    const { data: prof } = await supabase.from('profissionais')
      .select('comissao_pct, nome, email').eq('id', profissional_id).single();

    // Cria o agendamento já confirmado
    const { data: agendamento, error } = await supabase.from('agendamentos')
      .insert({
        salao_id, cliente_id: cliente.id, profissional_id,
        data_hora, duracao_min: servico.duracao_min,
        status: 'confirmado', valor_total: precoEfetivo,
        origem: 'app_cliente'
      })
      .select().single();

    if (error) throw error;

    // Cria registro em agendamento_servicos
    const cpct = servico.comissao_pct ?? prof?.comissao_pct ?? 40;
    await supabase.from('agendamento_servicos').insert({
      agendamento_id: agendamento.id, servico_id: servico.id,
      preco: precoEfetivo, comissao_pct: cpct,
      comissao_valor: (precoEfetivo * cpct) / 100
    });

    // Cria lançamento financeiro pendente
    try {
      await supabase.from('lancamentos').insert({
        salao_id, agendamento_id: agendamento.id, cliente_id: cliente.id, tipo: 'entrada',
        categoria: 'Serviço', descricao: servico.nome + ' - ' + nome,
        valor: precoEfetivo, data, pago: false
      });
    } catch(lancErr) { console.log('Lancamento nao criado:', lancErr.message); }

    // Notificação por e-mail pro profissional — o link público de agendamento
    // é um caminho SEPARADO do agendamento criado pelo painel admin, então
    // precisa da própria chamada (não reaproveita a lógica de /api/agendamentos)
    if (prof && prof.email) {
      notificarProfissionalNovoAgendamento(prof.email, prof.nome, nome, data_hora, [servico.nome], precoEfetivo)
        .then(r => {
          if (!r.enviado) console.error('Notificação de agendamento (link público) NÃO enviada pro profissional ' + prof.email + ': ' + r.motivo);
        }).catch(e => console.error('Erro inesperado ao notificar profissional (link público):', e.message));
    } else {
      console.log('Profissional ' + profissional_id + ' sem e-mail cadastrado — notificação (link público) não enviada.');
    }

    res.status(201).json({
      message: 'Agendamento confirmado!',
      agendamento: {
        id: agendamento.id,
        servico: servico.nome,
        data: data, hora_inicio: hora_inicio,
        valor: precoEfetivo
      }
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Cliente cancela seu próprio agendamento pelo link público (validado por telefone)
app.post('/api/publico/cancelar/:agendamentoId', async (req, res) => {
  const { telefone } = req.body;
  if (!telefone) return res.status(422).json({ error: 'Telefone obrigatório para confirmar o cancelamento' });

  try {
    const { data: ag } = await supabase.from('agendamentos')
      .select('id, status, data_hora, cliente_id, clientes(telefone)')
      .eq('id', req.params.agendamentoId).single();

    if (!ag) return res.status(404).json({ error: 'Agendamento não encontrado' });

    const telefoneLimpo = telefone.replace(/\D/g, '');
    const telefoneCadastrado = (ag.clientes && ag.clientes.telefone || '').replace(/\D/g, '');
    if (telefoneLimpo !== telefoneCadastrado) {
      return res.status(403).json({ error: 'Telefone não corresponde ao agendamento' });
    }

    if (ag.status === 'cancelado') {
      return res.status(409).json({ error: 'Este agendamento já está cancelado' });
    }
    if (ag.status === 'concluido') {
      return res.status(409).json({ error: 'Este agendamento já foi concluído, não pode ser cancelado' });
    }

    await supabase.from('agendamentos').update({ status: 'cancelado' }).eq('id', ag.id);
    await supabase.from('lancamentos').update({ pago: false }).eq('agendamento_id', ag.id);

    res.json({ message: 'Agendamento cancelado com sucesso' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 404
app.use((req, res) => res.status(404).json({ error: 'Rota nao encontrada' }));

const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
  console.log('Beleza Pro API rodando na porta ' + PORT);
});
