import express from 'express';
import cookieParser from 'cookie-parser';
import jsonwebtoken from 'jsonwebtoken';
import mysql from 'mysql2';
import { fileURLToPath } from 'url';
import { dirname } from 'path';



const app = express();
app.use(express.json());
app.use(cookieParser());
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Configura la conexión a la base de datos MySQL
const db = mysql.createConnection({
  host: '---',
  user: '---',
  password: '---',
  database: '---',
});

db.connect((err) => {
  if (err) {
    console.error('Error al conectar a la base de datos: ' + err);
  } else {
    console.log('Conectado a la base de datos MySQL');
  }
});


const secretKey = 'secretKey';


function autToken(req, res, next) {
    const token = req.cookies.token;
  
    if (!token) {
      return res.status(401).json({ error: 'No se proporcionó token' });
    }
  
    jsonwebtoken.verify(token, secretKey, (err, user) => {
      if (err) {
        return res.status(403).json({ error: 'Token inválido' });
      }
      req.user = user; 
      next();
    });
  }
  app.get('/', (req, res) => {
    res.sendFile(`${__dirname}/index.html`);
  });
 
  app.get('/protegido', autToken, (req, res) => {
    res.json({ message: 'Esta es una ruta protegida' });
  });


app.post('/login', (req, res) => {
  const { username, password } = req.body;


  db.query(
    'SELECT * FROM usuarios WHERE username = ? AND password = ?',
    [username, password],
    (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).json({ error: 'Error en el servidor' });
      } else if (results.length > 0) {
        const user = results[0];
        const token = jsonwebtoken.sign({ id: user.id, username: user.username }, secretKey, {
          expiresIn: '5s', 
        });

        res.cookie('token', token, { httpOnly: true });
        res.status(200).json({ message: 'Inicio de sesión exitoso' });
      } else {
        res.status(401).json({ error: 'Credenciales incorrectas' });
      }
    }
  );
});


app.get('/protegido', (req, res) => {
  res.json({ message: 'Esta es una ruta protegida' });
});

app.listen(3000, () => {
  console.log('Servidor en ejecución en el puerto 3000');
});
