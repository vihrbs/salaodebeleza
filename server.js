const express = require('express');
const cors = require('cors');

const app = express();

app.use(cors());
app.use(express.json());

// rota raiz (IMPORTANTE)
app.get('/', (req, res) => {
  res.send('API rodando');
});

// rota health
app.get('/health', (req, res) => {
  res.send('ok');
});

const PORT = process.env.PORT || 3001;

app.listen(PORT, '0.0.0.0', () => {
  console.log('Servidor rodando na porta ' + PORT);
});
