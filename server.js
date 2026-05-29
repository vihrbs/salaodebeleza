const express = require('express');
const cors = require('cors');

const app = express();

app.use(cors());
app.use(express.json());

// rota raiz
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

// cadastro (SIMULAÇÃO)
app.post('/cadastro', (req, res) => {
  const dados = req.body;

  console.log('Dados recebidos:', dados);

  res.json({
    sucesso: true,
    mensagem: 'Cadastro realizado com sucesso',
    dados: dados
  });
});

// login (SIMULAÇÃO)
app.post('/login', (req, res) => {
  const { email, senha } = req.body;

  if (email && senha) {
    return res.json({
      sucesso: true,
      mensagem: 'Login realizado'
    });
  }

  res.status(400).json({
    sucesso: false,
    mensagem: 'Dados inválidos'
  });
});

const PORT = process.env.PORT || 3001;

app.listen(PORT, '0.0.0.0', () => {
  console.log('Servidor rodando na porta ' + PORT);
});
