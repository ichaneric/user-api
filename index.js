const express = require('express');
const app = express();
const port = 3000;

app.use(express.json()); // Middleware to parse JSON bodies

app.get('/', (req, res) => {
  res.send('User API is running!');
});

app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});