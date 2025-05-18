require('dotenv').config();
const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { initializeApp } = require('firebase/app');
const { getDatabase, ref, set, update, get, child } = require('firebase/database');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = 3000;

// Firebase config
const firebaseConfig = {
  apiKey: process.env.FIREBASE_API_KEY,
  authDomain: process.env.FIREBASE_AUTH_DOMAIN,
  projectId: process.env.FIREBASE_PROJECT_ID,
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.FIREBASE_APP_ID,
  databaseURL: process.env.FIREBASE_DATABASE_URL,
};

const firebaseApp = initializeApp(firebaseConfig);
const db = getDatabase(firebaseApp);

const otps = new Map(); // { email: { code, expiresAt, verified } }

// Configura tu transporte de correo
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

app.post('/otp/send', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email requerido' });

  const code = crypto.randomInt(100000, 999999).toString();
  const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutos

  otps.set(email, { code, expiresAt, verified: false });

  try {
    await transporter.sendMail({
      from: `OTP <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Tu código de verificación',
      text: `Tu código es: ${code}. Expira en 5 minutos.`,
    });

    await set(ref(db, `otp/${email.replace(/[.#$\[\]]/g, '_')}`), {
      code,
      verified: false,
      expiresAt,
      createdAt: Date.now(),
    });

    res.json({ message: 'OTP enviado' });
  } catch (err) {
    console.error('Error al enviar OTP:', err);
    res.status(500).json({ error: 'No se pudo enviar el OTP' });
  }
});

app.post('/otp/verify', async (req, res) => {
  const { email, code } = req.body;
  const data = otps.get(email);

  if (!data) return res.status(400).json({ error: 'No se encontró un código para este email' });
  if (Date.now() > data.expiresAt) return res.status(400).json({ error: 'El código ha expirado' });
  if (data.code !== code) return res.status(400).json({ error: 'Código incorrecto' });

  data.verified = true;
  otps.set(email, data);

  try {
    await update(ref(db, `otp/${email.replace(/[.#$\[\]]/g, '_')}`), { verified: true });
  } catch (error) {
    console.error('Error actualizando OTP en Realtime Database:', error);
  }

  res.json({ message: 'OTP verificado correctamente' });
});

app.post('/form/submit', async (req, res) => {
  const formData = req.body;

  if (!formData.email || !formData.nombre) {
    return res.status(400).json({ error: 'Faltan campos obligatorios' });
  }

  const otpData = otps.get(formData.email);
  if (!otpData || !otpData.verified) {
    return res.status(403).json({ error: 'Debes verificar tu OTP antes de enviar el formulario' });
  }

  try {
    await set(ref(db, `solicitudes/${formData.email.replace(/[.#$\[\]]/g, '_')}`), formData);
    otps.delete(formData.email); // limpiar OTP después de guardar
    res.json({ message: 'Formulario guardado correctamente' });
  } catch (error) {
    console.error('Error guardando el formulario:', error);
    res.status(500).json({ error: 'No se pudo guardar el formulario' });
  }
});

app.get('/form/list', async (req, res) => {
  try {
    const snapshot = await get(child(ref(db), 'solicitudes'));
    if (!snapshot.exists()) {
      return res.json([]);
    }
    res.json(snapshot.val());
  } catch (error) {
    console.error('Error obteniendo formularios:', error);
    res.status(500).json({ error: 'No se pudo obtener la lista de formularios' });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
