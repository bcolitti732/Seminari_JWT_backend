// src/routes/user_routes.ts
import express from 'express';
import { registerCtrl, loginCtrl, googleAuthCtrl, googleAuthCallback } from "../auth/auth_controller.js";
import { checkJwt } from '../../middleware/session.js';
import { verifyRefreshToken, generateToken } from '../../utils/jwt.handle.js';
import UserModel from '../users/user_models.js';


const router = express.Router();

/**
 * @swagger
 * components:
 *   schemas:
 *     AuthRegister:
 *       type: object
 *       required:
 *         - name
 *         - password
 *         - email
 *       properties:
 *         name:
 *           type: string
 *           description: El nombre completo del usuario
 *         password:
 *           type: string
 *           description: La contraseña del usuario
 *         age:
 *           type: integer
 *           description: La edad del usuario
 *           default: 0
 *         email:
 *           type: string
 *           description: El correo electrónico del usuario
 *       example:
 *         name: Usuario Ejemplo
 *         password: contraseña123
 *         age: 30
 *         email: usuario@example.com
 *     AuthLogin:
 *       type: object
 *       required:
 *         - email
 *         - password
 *       properties:
 *         email:
 *           type: string
 *           description: El email del usuario
 *         password:
 *           type: string
 *           description: La contraseña del usuario
 *       example:
 *         email: usuario@ejemplo.com
 *         password: contraseña123
 */

/**
 * @swagger
 * /api/auth/register:
 *   post:
 *     summary: Registra un nuevo usuario
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/AuthRegister'
 *     responses:
 *       200:
 *         description: Usuario registrado exitosamente
 *       400:
 *         description: Error en la solicitud
 */
router.post("/auth/register", registerCtrl);

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Inicia sesión un usuario
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/AuthLogin'
 *     responses:
 *       200:
 *         description: Inicio de sesión exitoso
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 user:
 *                   type: object
 *                   description: Información del usuario
 *                 token:
 *                   type: string
 *                   description: Token JWT generado
 *                 refreshToken:
 *                   type: string
 *                   description: Refresh token generado
 *       400:
 *         description: Error en la solicitud
 */
router.post("/auth/login", loginCtrl);

/**
 * @swagger
 * /api/auth/google:
 *   get:
 *     summary: Redirige al usuario a Google para autenticarse
 *     tags: [Auth]
 *     responses:
 *       302:
 *         description: Redirección a Google para autenticación
 */
router.get('/auth/google', googleAuthCtrl);

/**
 * @swagger
 * /api/auth/google/callback:
 *   get:
 *     summary: Callback de Google OAuth
 *     tags: [Auth]
 *     responses:
 *       200:
 *         description: Autenticación exitosa, redirige al frontend con el token y el email
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: Token JWT generado
 *                 email:
 *                   type: string
 *                   description: Correo electrónico del usuario autenticado
 *       400:
 *         description: Error en la autenticación
 */
router.get('/auth/google/callback', googleAuthCallback);

/**
 * @swagger
 * /api/auth/protected:
 *   get:
 *     summary: Ruta protegida que requiere autenticación
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Acceso permitido
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Mensaje de éxito
 *                 user:
 *                   type: object
 *                   description: Información del usuario autenticado
 *       401:
 *         description: Token inválido o no proporcionado
 */
router.get('/auth/protected', checkJwt, (req, res) => {
    res.json({
        message: 'Acceso permitido a la ruta protegida',
        user: req.user, // Información del usuario extraída del token
    });
}
);


/**
 * @swagger
 * /api/auth/refresh:
 *   post:
 *     summary: Renueva el access token utilizando el refresh token
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               refreshToken:
 *                 type: string
 *                 description: Refresh token válido
 *     responses:
 *       200:
 *         description: Token renovado exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: Nuevo access token
 *       400:
 *         description: Refresh token no proporcionado
 *       401:
 *         description: Refresh token inválido o expirado
 */
router.post('/auth/refresh', async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(400).json({ message: 'Refresh token es requerido' });
    }

    try {
        const payload = verifyRefreshToken(refreshToken);

        if (!payload || typeof payload !== 'object' || !('id' in payload)) {
            return res.status(401).json({ message: 'Refresh token inválido o expirado' });
        }

        // Obtener al usuario desde la base de datos
        const user = await UserModel.findById(payload.id);
        if (!user) {
            return res.status(401).json({ message: 'Usuario no encontrado' });
        }

        // Generar nuevo access token
        const newToken = generateToken(user.id, user.email);
        return res.json({ token: newToken });

    } catch (error) {
        console.error('Error al procesar el refresh token:', error);
        return res.status(500).json({ message: 'Error interno del servidor' });
    }
});


export default router;