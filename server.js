const express  = require('express');
const cors     = require('cors');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

// ── Supabase ─────────────────────────────────────────
const { createClient } = require('@supabase/supabase-js');
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const JWT_SECRET = process.env.JWT_SECRET || 'beleza_pro_secret_2026';

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
      .from('usuarios').select('id, nome, email, perfil, salao_id, ativo')
      .eq('id', payload.sub).single();
    if (!usuario || !usuario.ativo) return res.status(401).json({ error: 'Usuário inválido' });
    req.user     = usuario;
    req.salao_id = usuario.salao_id;
    next();
  } catch(e) {
    return res.status(401).json({ error: 'Token inválido ou expirado' });
  }
}

// ── Health ───────────────────────────────────────────
app.get('/',       (req, res) => res.json({ mensagem: 'Beleza Pro API rodando' }));
app.get('/health', (req, res) => res.json({ status: 'ok', version: '2.0.0' }));

// ═══════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════

// REGISTER — cria salão + admin
app.post('/api/auth/register', async (req, res) => {
  const { nome_salao, nome, email, senha, telefone } = req.body;
  if (!nome_salao || !nome || !email || !senha) {
    return res.status(422).json({ error: 'Preencha todos os campos obrigatórios' });
  }
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

    const { data: usuario, error: userErr } = await supabase
      .from('usuarios')
      .insert({ salao_id: salao.id, nome, email, senha_hash, perfil: 'admin' })
      .select('id, nome, email, perfil, salao_id').single();
    if (userErr) throw userErr;

    const token = jwt.sign({ sub: usuario.id }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, usuario: { ...usuario, saloes: salao }, salao });
  } catch(e) {
    console.error('Register error:', e);
    res.status(500).json({ error: 'Erro ao criar conta: ' + e.message });
  }
});

// LOGIN
app.post('/api/auth/login', async (req, res) => {
  const { email, senha } = req.body;
  if (!email || !senha) return res.status(422).json({ error: 'Email e senha obrigatórios' });
  try {
    const { data: usuario } = await supabase
      .from('usuarios')
      .select('id, nome, email, senha_hash, perfil, ativo, salao_id, saloes(id, nome, slug, trial_ate)')
      .eq('email', email).single();
    if (!usuario) return res.status(401).json({ error: 'Email ou senha incorretos' });
    if (!usuario.ativo) return res.status(403).json({ error: 'Conta desativada' });

    const ok = await bcrypt.compare(senha, usuario.senha_hash);
    if (!ok) return res.status(401).json({ error: 'Email ou senha incorretos' });

    await supabase.from('usuarios').update({ ultimo_login: new Date() }).eq('id', usuario.id);

    const token = jwt.sign({ sub: usuario.id }, JWT_SECRET, { expiresIn: '7d' });
    const { senha_hash, ...userSafe } = usuario;
    res.json({ token, usuario: userSafe });
  } catch(e) {
    res.status(500).json({ error: 'Erro ao fazer login' });
  }
});

// ME
app.get('/api/auth/me', auth, async (req, res) => {
  const { data } = await supabase
    .from('usuarios')
    .select('id, nome, email, perfil, ultimo_login, saloes(id, nome, slug, trial_ate)')
    .eq('id', req.user.id).single();
  res.json(data);
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

app.post('/api/profissionais', auth, async (req, res) => {
  const { data, error } = await supabase
    .from('profissionais')
    .insert({ ...req.body, salao_id: req.salao_id })
    .select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});

app.put('/api/profissionais/:id', auth, async (req, res) => {
  const { data, error } = await supabase
    .from('profissionais').update(req.body)
    .eq('id', req.params.id).eq('salao_id', req.salao_id).select().single();
  if (error || !data) return res.status(404).json({ error: 'Não encontrado' });
  res.json(data);
});

app.delete('/api/profissionais/:id', auth, async (req, res) => {
  await supabase.from('profissionais').update({ ativo: false })
    .eq('id', req.params.id).eq('salao_id', req.salao_id);
  res.json({ message: 'Desativado' });
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

app.post('/api/servicos', auth, async (req, res) => {
  const { data, error } = await supabase
    .from('servicos')
    .insert({ ...req.body, salao_id: req.salao_id })
    .select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});

app.put('/api/servicos/:id', auth, async (req, res) => {
  const { data, error } = await supabase
    .from('servicos').update(req.body)
    .eq('id', req.params.id).eq('salao_id', req.salao_id).select().single();
  if (error || !data) return res.status(404).json({ error: 'Não encontrado' });
  res.json(data);
});

app.delete('/api/servicos/:id', auth, async (req, res) => {
  await supabase.from('servicos').update({ ativo: false })
    .eq('id', req.params.id).eq('salao_id', req.salao_id);
  res.json({ message: 'Desativado' });
});

// ═══════════════════════════════════════════════════
// CLIENTES
// ═══════════════════════════════════════════════════
app.get('/api/clientes', auth, async (req, res) => {
  const { q, limit = 100, page = 1 } = req.query;
  const offset = (page - 1) * limit;
  let query = supabase.from('clientes').select('*', { count: 'exact' })
    .eq('salao_id', req.salao_id).order('nome').range(offset, offset + Number(limit) - 1);
  if (q) query = query.ilike('nome', `%${q}%`);
  const { data, count, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json({ data: data || [], total: count });
});

app.post('/api/clientes', auth, async (req, res) => {
  const { data, error } = await supabase
    .from('clientes')
    .insert({ ...req.body, salao_id: req.salao_id })
    .select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
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
  const { data, data_inicio, data_fim, profissional_id, status } = req.query;
  let q = supabase.from('agendamentos')
    .select(`id, data_hora, duracao_min, status, valor_total, forma_pgto, observacoes, origem,
             clientes(id, nome, telefone),
             profissionais(id, nome, cor_agenda),
             agendamento_servicos(id, preco, servicos(id, nome, duracao_min))`)
    .eq('salao_id', req.salao_id).order('data_hora');

  if (data) {
    q = q.gte('data_hora', data + 'T00:00:00').lte('data_hora', data + 'T23:59:59');
  } else {
    if (data_inicio) q = q.gte('data_hora', data_inicio + 'T00:00:00');
    if (data_fim)    q = q.lte('data_hora', data_fim + 'T23:59:59');
  }
  if (profissional_id) q = q.eq('profissional_id', profissional_id);
  if (status)          q = q.eq('status', status);

  const { data: rows, error } = await q;
  if (error) return res.status(500).json({ error: error.message });
  res.json(rows || []);
});

app.post('/api/agendamentos', auth, async (req, res) => {
  const { cliente_id, profissional_id, data_hora, servicos, observacoes, origem } = req.body;
  if (!cliente_id || !profissional_id || !data_hora || !servicos || !servicos.length) {
    return res.status(422).json({ error: 'Dados incompletos' });
  }
  try {
    const { data: srvcs } = await supabase
      .from('servicos').select('id, preco, duracao_min, comissao_pct')
      .in('id', servicos).eq('salao_id', req.salao_id);

    const { data: prof } = await supabase
      .from('profissionais').select('comissao_pct').eq('id', profissional_id).single();

    const duracao_total = (srvcs || []).reduce((s, sv) => s + sv.duracao_min, 0);
    const valor_total   = (srvcs || []).reduce((s, sv) => s + Number(sv.preco), 0);

    const { data: ag, error } = await supabase
      .from('agendamentos')
      .insert({ salao_id: req.salao_id, cliente_id, profissional_id, data_hora,
                duracao_min: duracao_total, valor_total, origem: origem || 'backoffice', observacoes })
      .select().single();
    if (error) throw error;

    const linhas = (srvcs || []).map(sv => {
      const cpct  = sv.comissao_pct ?? prof?.comissao_pct ?? 40;
      return { agendamento_id: ag.id, servico_id: sv.id, preco: sv.preco,
               comissao_pct: cpct, comissao_valor: (Number(sv.preco) * cpct) / 100 };
    });
    if (linhas.length) await supabase.from('agendamento_servicos').insert(linhas);

    await supabase.from('lancamentos').insert({
      salao_id: req.salao_id, agendamento_id: ag.id, tipo: 'entrada',
      categoria: 'Serviço', descricao: 'Agendamento #' + ag.id.slice(-6).toUpperCase(),
      valor: valor_total, data: data_hora.split('T')[0], pago: false
    });

    res.status(201).json(ag);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch('/api/agendamentos/:id/status', auth, async (req, res) => {
  const { status, forma_pgto } = req.body;
  const updates = { status };
  if (forma_pgto) updates.forma_pgto = forma_pgto;
  const { data, error } = await supabase
    .from('agendamentos').update(updates)
    .eq('id', req.params.id).eq('salao_id', req.salao_id).select().single();
  if (error || !data) return res.status(404).json({ error: 'Não encontrado' });
  if (status === 'concluido') {
    await supabase.from('lancamentos')
      .update({ pago: true, forma_pgto }).eq('agendamento_id', req.params.id);
  }
  res.json(data);
});

// ═══════════════════════════════════════════════════
// DASHBOARD
// ═══════════════════════════════════════════════════
app.get('/api/dashboard/kpis', auth, async (req, res) => {
  const hoje = new Date().toISOString().split('T')[0];
  const inicioMes = hoje.slice(0, 7) + '-01';
  const [{ count: agHoje }, { data: lancHoje }, { count: clientes }, { data: novos }] = await Promise.all([
    supabase.from('agendamentos').select('id', { count: 'exact' })
      .eq('salao_id', req.salao_id)
      .gte('data_hora', hoje + 'T00:00:00').lte('data_hora', hoje + 'T23:59:59')
      .not('status', 'in', '("cancelado","nao_compareceu")'),
    supabase.from('lancamentos').select('tipo, valor')
      .eq('salao_id', req.salao_id).eq('data', hoje).eq('pago', true),
    supabase.from('clientes').select('id', { count: 'exact' })
      .eq('salao_id', req.salao_id).eq('ativo', true),
    supabase.from('clientes').select('id')
      .eq('salao_id', req.salao_id).gte('created_at', inicioMes + 'T00:00:00'),
  ]);
  const faturamento = (lancHoje || [])
    .filter(l => l.tipo === 'entrada').reduce((s, l) => s + Number(l.valor), 0);
  res.json({ agendamentos_hoje: agHoje || 0, faturamento_hoje: faturamento,
             clientes_ativos: clientes || 0, novos_clientes_mes: novos?.length || 0 });
});

app.get('/api/dashboard/agenda-hoje', auth, async (req, res) => {
  const hoje = new Date().toISOString().split('T')[0];
  const { data } = await supabase.from('agendamentos')
    .select(`id, data_hora, status, valor_total,
             clientes(nome, telefone), profissionais(nome, cor_agenda),
             agendamento_servicos(servicos(nome))`)
    .eq('salao_id', req.salao_id)
    .gte('data_hora', hoje + 'T00:00:00').lte('data_hora', hoje + 'T23:59:59')
    .not('status', 'eq', 'cancelado').order('data_hora');
  res.json(data || []);
});

app.get('/api/dashboard/top-servicos', auth, async (req, res) => {
  const inicioMes = new Date().toISOString().slice(0, 7) + '-01';
  const { data } = await supabase.from('agendamento_servicos')
    .select('servicos(nome), preco, agendamentos!inner(data_hora, salao_id, status)')
    .eq('agendamentos.salao_id', req.salao_id)
    .eq('agendamentos.status', 'concluido')
    .gte('agendamentos.data_hora', inicioMes + 'T00:00:00');
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
app.get('/api/financeiro/resumo', auth, async (req, res) => {
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

app.get('/api/financeiro/lancamentos', auth, async (req, res) => {
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

app.post('/api/financeiro/lancamentos', auth, async (req, res) => {
  const { data, error } = await supabase
    .from('lancamentos').insert({ ...req.body, salao_id: req.salao_id }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});

// ═══════════════════════════════════════════════════
// ESTOQUE
// ═══════════════════════════════════════════════════
app.get('/api/estoque', auth, async (req, res) => {
  const { q } = req.query;
  let query = supabase.from('produtos').select('*')
    .eq('salao_id', req.salao_id).eq('ativo', true).order('nome');
  if (q) query = query.ilike('nome', `%${q}%`);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data || []);
});

app.get('/api/estoque/alertas', auth, async (req, res) => {
  const { data } = await supabase.from('produtos').select('id, nome, qtd_atual, qtd_minima, categoria')
    .eq('salao_id', req.salao_id).eq('ativo', true);
  const alertas = (data || []).filter(p => Number(p.qtd_atual) < Number(p.qtd_minima));
  res.json(alertas);
});

app.post('/api/estoque', auth, async (req, res) => {
  const { data, error } = await supabase
    .from('produtos').insert({ ...req.body, salao_id: req.salao_id }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});

app.put('/api/estoque/:id', auth, async (req, res) => {
  const { data, error } = await supabase.from('produtos').update(req.body)
    .eq('id', req.params.id).eq('salao_id', req.salao_id).select().single();
  if (error || !data) return res.status(404).json({ error: 'Não encontrado' });
  res.json(data);
});

// ═══════════════════════════════════════════════════
// COMISSÕES
// ═══════════════════════════════════════════════════
app.get('/api/comissoes', auth, async (req, res) => {
  const { data: profissionais } = await supabase.from('profissionais')
    .select('id, nome, comissao_pct, cor_agenda').eq('salao_id', req.salao_id).eq('ativo', true);
  if (!profissionais) return res.json([]);
  const now = new Date();
  const ini = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-01`;
  const fim = new Date(now.getFullYear(), now.getMonth()+1, 0).toISOString().split('T')[0];
  const resultado = await Promise.all(profissionais.map(async p => {
    const { data: svcs } = await supabase.from('agendamento_servicos')
      .select('preco, comissao_valor, agendamentos!inner(data_hora, status, profissional_id)')
      .eq('agendamentos.profissional_id', p.id)
      .eq('agendamentos.status', 'concluido')
      .gte('agendamentos.data_hora', ini + 'T00:00:00')
      .lte('agendamentos.data_hora', fim + 'T23:59:59');
    const total_bruto    = (svcs || []).reduce((s, sv) => s + Number(sv.preco || 0), 0);
    const total_comissao = (svcs || []).reduce((s, sv) => s + Number(sv.comissao_valor || 0), 0);
    const { data: fechamento } = await supabase.from('fechamentos_comissao')
      .select('id, status, pago_em').eq('salao_id', req.salao_id)
      .eq('profissional_id', p.id).eq('periodo_inicio', ini).maybeSingle();
    return { ...p, total_servicos: svcs?.length || 0, total_bruto, total_comissao, fechamento };
  }));
  res.json(resultado);
});

app.post('/api/comissoes/fechar', auth, async (req, res) => {
  const { profissional_id, total_comissao } = req.body;
  const now = new Date();
  const ini = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-01`;
  const fim = new Date(now.getFullYear(), now.getMonth()+1, 0).toISOString().split('T')[0];
  const { data, error } = await supabase.from('fechamentos_comissao')
    .upsert({ salao_id: req.salao_id, profissional_id, periodo_inicio: ini, periodo_fim: fim,
              total_comissao: total_comissao || 0, status: 'pago', pago_em: new Date() },
             { onConflict: 'salao_id,profissional_id,periodo_inicio' })
    .select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ═══════════════════════════════════════════════════
// SALÃO
// ═══════════════════════════════════════════════════
app.get('/api/saloes/meu', auth, async (req, res) => {
  const { data } = await supabase.from('saloes')
    .select('*, planos(nome, features)').eq('id', req.salao_id).single();
  res.json(data);
});

app.put('/api/saloes/meu', auth, async (req, res) => {
  const { nome, telefone, whatsapp, email, endereco, cidade, estado } = req.body;
  const { data, error } = await supabase.from('saloes')
    .update({ nome, telefone, whatsapp, email, endereco, cidade, estado })
    .eq('id', req.salao_id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ═══════════════════════════════════════════════════
// 404
// ═══════════════════════════════════════════════════
app.use((req, res) => res.status(404).json({ error: 'Rota não encontrada' }));

// ═══════════════════════════════════════════════════
// START
// ═══════════════════════════════════════════════════
const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
  console.log('Beleza Pro API rodando na porta ' + PORT);
});
