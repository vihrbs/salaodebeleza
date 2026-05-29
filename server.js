const express = require('express');
const cors = require('cors');

const app = express();

app.use(cors());
app.use(express.json());

/* =========================
   ROTAS BÁSICAS
========================= */

// raiz
app.get('/', (req, res) => {
  res.json({ mensagem: 'API rodando' });
});

// health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// teste
app.get('/teste', (req, res) => {
  res.json({ mensagem: 'API funcionando' });
});

/* =========================
   AUTENTICAÇÃO
========================= */

// LOGIN (rota que seu frontend está usando)
app.post('/api/auth/login', (req, res) => {
  const { email, senha } = req.body;

  if (email && senha) {
    return res.json({
      sucesso: true,
      mensagem: 'Login realizado com sucesso',
      usuario: {
        email
      }
    });
  }

  return res.status(400).json({
    sucesso: false,
    mensagem: 'Email ou senha inválidos'
  });
});

// CADASTRO
app.post('/api/auth/register', (req, res) => {
  const dados = req.body;

  console.log('Cadastro recebido:', dados);

  return res.json({
    sucesso: true,
    mensagem: 'Usuário cadastrado com sucesso',
    usuario: dados
  });
});

/* =========================
   SERVER
========================= */

const PORT = process.env.PORT || 3001;

app.listen(PORT, '0.0.0.0', () => {
  console.log('Servidor rodando na porta ' + PORT);
});
