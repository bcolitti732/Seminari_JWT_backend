import pkg from "jsonwebtoken";
const { sign, verify } = pkg;   //Importamos las funciones sign y verify de la librería jsonwebtoken
const JWT_SECRET = process.env.JWT_SECRET || "token.010101010101";

//No debemos pasar información sensible en el payload, en este caso vamos a pasar como parametro el ID del usuario
const generateToken = (id: string, email: string) => {
    const jwt = sign(
        { id, email },
        JWT_SECRET,
        { expiresIn: '1h' }
    );
    return jwt;
};


const verifyToken = (jwt: string) => {
    const isOk = verify(jwt, JWT_SECRET);
    return isOk;

};

const generateRefreshToken = (id: string) => {
    const refreshToken = sign(
        { id }, 
        JWT_SECRET,
        { expiresIn: '7d' }
    );
    return refreshToken;
};

const verifyRefreshToken = (refreshToken: string) => {
    try {
        const isOk = verify(refreshToken, JWT_SECRET);
        return isOk;
    } catch (error) {
        return null; 
    }
};

export { generateToken, verifyToken };
export { generateRefreshToken, verifyRefreshToken };