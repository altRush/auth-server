import express, { Request, Response } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

const app = express();

app.use(express.json());

let refreshTokens = [] as string[];

app.post('/token', (req: Request, res: Response) => {
  const refreshToken = req.body.token;
  if (refreshToken == null) return res.sendStatus(401);
  // if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);

  try {
    const payload = jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET!,
    ) as JwtPayload;

    const username = payload?.username;

    const accessToken = generateAccessToken({ username });
    res.status(200).json({ accessToken: accessToken });
  } catch (err) {
    if (err) return res.sendStatus(403);
  }
});

app.post('/logout', (req, res) => {
  refreshTokens = refreshTokens.filter((token) => token !== req.body.token);
  res.sendStatus(204);
});

interface User {
  username: string;
}

app.post('/login', (req, res) => {
  // Authenticate User

  const username = req.body.username;
  const user: User = { username };

  const accessToken = generateAccessToken(user);
  const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET!);

  refreshTokens.push(refreshToken);
  res.status(200).json({ accessToken, refreshToken });
});

function generateAccessToken(user: User) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET!, { expiresIn: '15s' });
}

app.listen(+process.env.PORT!);
