const express = require('express');
const cors = require('cors');

const app = express();

app.use(cors());
app.use(express.json());

app.get('/health', (req, res) => {
  res.send('ok');
});

const PORT = process.env.PORT;

app.listen(PORT, () => {
  console.log('Servidor rodando na porta ' + PORT);
});
