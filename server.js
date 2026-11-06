const fs = require('fs');
const https = require('https');
const http = require('http');
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();

const PORT = process.env.PORT || 3000;
const USE_HTTPS = process.env.USE_HTTPS === 'true';

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: 'tcc-seguridad-informatica',
  resave: false,
  saveUninitialized: false,
}));

const db = new sqlite3.Database(':memory:');

db.serialize(() => {
  db.run(`CREATE TABLE usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario TEXT UNIQUE,
    password TEXT
  )`);

  db.run(`CREATE TABLE inventario (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    producto TEXT,
    cantidad INTEGER,
    precio REAL
  )`);

  db.run(`CREATE TABLE ventas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    producto TEXT,
    cantidad INTEGER,
    fecha TEXT
  )`);

  db.run(`INSERT INTO usuarios (usuario, password) VALUES ('cajero', 'clave123')`);

  const productos = [
    ['Resma de papel carta', 50, 12000],
    ['Cuaderno 100 hojas', 80, 4500],
    ['Caja de lapiceros', 30, 9000],
  ];
  const stmt = db.prepare('INSERT INTO inventario (producto, cantidad, precio) VALUES (?, ?, ?)');
  productos.forEach((p) => stmt.run(p));
  stmt.finalize();
});

function requiereLogin(req, res, next) {
  if (req.session && req.session.usuario) return next();
  return res.redirect('/login');
}

app.get('/', (req, res) => res.redirect('/login'));

app.get('/login', (req, res) => {
  res.send(`
    <h2>Papelería - Inicio de sesión</h2>
    <form method="POST" action="/login">
      <label>Usuario: <input name="usuario" /></label><br/>
      <label>Contraseña: <input name="password" type="password" /></label><br/>
      <button type="submit">Entrar</button>
    </form>
  `);
});

app.post('/login', (req, res) => {
  const { usuario, password } = req.body;
  db.get(
    'SELECT * FROM usuarios WHERE usuario = ? AND password = ?',
    [usuario, password],
    (err, row) => {
      if (row) {
        req.session.usuario = usuario;
        return res.redirect('/inventario');
      }
      return res.send('Credenciales incorrectas. <a href="/login">Volver</a>');
    }
  );
});

app.get('/inventario', requiereLogin, (req, res) => {
  db.all('SELECT * FROM inventario', (err, filas) => {
    let filasHtml = filas
      .map((f) => `<tr><td>${f.id}</td><td>${f.producto}</td><td>${f.cantidad}</td><td>${f.precio}</td></tr>`)
      .join('');
    res.send(`
      <h2>Inventario</h2>
      <table border="1" cellpadding="6">
        <tr><th>ID</th><th>Producto</th><th>Cantidad</th><th>Precio</th></tr>
        ${filasHtml}
      </table>
      <h3>Registrar venta</h3>
      <form method="POST" action="/venta">
        <label>Producto: <input name="producto" /></label><br/>
        <label>Cantidad: <input name="cantidad" type="number" /></label><br/>
        <button type="submit">Registrar</button>
      </form>
      <p><a href="/logout">Cerrar sesión</a></p>
    `);
  });
});

app.post('/venta', requiereLogin, (req, res) => {
  const { producto, cantidad } = req.body;
  const fecha = new Date().toISOString();
  db.run(
    'INSERT INTO ventas (producto, cantidad, fecha) VALUES (?, ?, ?)',
    [producto, cantidad, fecha],
    () => res.redirect('/inventario')
  );
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

if (USE_HTTPS) {
  const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
  };
  https.createServer(options, app).listen(PORT, () => {
    console.log(`[HTTPS] App de caja escuchando en el puerto ${PORT}`);
  });
} else {
  http.createServer(app).listen(PORT, () => {
    console.log(`[HTTP] App de caja escuchando en el puerto ${PORT} (versión vulnerable, sin cifrar)`);
  });
}
