import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import session from "express-session";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

const users = new Map();

app.set("trust proxy", 1);
app.use(express.json());

app.use(
  session({
    secret:
      process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: "auto",
    },
  }),
);

app.use(express.static("public"));

app.use(
  "/webauthn",
  express.static(
    path.join(
      __dirname,
      "node_modules",
      "@simplewebauthn",
      "browser",
      "dist",
      "bundle",
    ),
  ),
);

function getWebAuthnConfig(req) {
  const host = req.get("host");

  return {
    rpID: host.split(":")[0],
    origin: `${req.protocol}://${host}`,
  };
}

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: "로그인이 필요합니다.",
    });
  }

  next();
}

/* 카드 2: 패스키 등록 */

app.post("/api/passkeys/register/options", (req, res) => {
  const username = String(req.body.username || "").trim();

  if (username.length < 2 || username.length > 30) {
    return res.status(400).json({
      error: "이름은 2~30자로 입력하세요.",
    });
  }

  let user = users.get(username);

  if (!user) {
    user = {
      id: crypto.randomBytes(16).toString("base64url"),
      username,
      credentials: [],
    };

    users.set(username, user);
  }

  const { rpID } = getWebAuthnConfig(req);

  const options = generateRegistrationOptions({
    rpName: "김현승의 자기소개",
    rpID,
    userName: user.username,
    userID: new TextEncoder().encode(user.id),
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "required",
    },
    excludeCredentials: user.credentials.map((credential) => ({
      id: credential.id,
      transports: credential.transports,
    })),
  });

  req.session.registration = {
    userId: user.id,
    challenge: options.challenge,
  };

  res.json(options);
});

app.post("/api/passkeys/register/verify", async (req, res) => {
  const pending = req.session.registration;

  if (!pending) {
    return res.status(400).json({
      error: "등록 요청이 만료되었습니다. 다시 시도하세요.",
    });
  }

  const user = [...users.values()].find((item) => item.id === pending.userId);

  const { rpID, origin } = getWebAuthnConfig(req);

  try {
    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: pending.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });

    if (!verification.verified || !verification.registrationInfo) {
      throw new Error("패스키 검증에 실패했습니다.");
    }

    const { credential } = verification.registrationInfo;

    user.credentials.push({
      id: credential.id,
      publicKey: credential.publicKey,
      counter: credential.counter,
      transports: req.body.response?.transports || [],
      createdAt: new Date().toISOString(),
    });

    delete req.session.registration;
    req.session.userId = user.id;

    res.json({
      verified: true,
      username: user.username,
      passkeyCount: user.credentials.length,
    });
  } catch (error) {
    res.status(400).json({
      error: error.message || "패스키 등록에 실패했습니다.",
    });
  }
});

/* 카드 3: 패스키 로그인 */

app.post("/api/passkeys/login/options", (req, res) => {
  const { rpID } = getWebAuthnConfig(req);

  const options = generateAuthenticationOptions({
    rpID,
    userVerification: "required",
  });

  req.session.authentication = {
    challenge: options.challenge,
  };

  res.json(options);
});

app.post("/api/passkeys/login/verify", async (req, res) => {
  const pending = req.session.authentication;

  if (!pending) {
    return res.status(400).json({
      error: "로그인 요청이 만료되었습니다. 다시 시도하세요.",
    });
  }

  let user;
  let credential;

  for (const candidate of users.values()) {
    const found = candidate.credentials.find((item) => item.id === req.body.id);

    if (found) {
      user = candidate;
      credential = found;
      break;
    }
  }

  if (!user || !credential) {
    return res.status(400).json({
      error: "등록되지 않은 패스키입니다.",
    });
  }

  const { rpID, origin } = getWebAuthnConfig(req);

  try {
    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: pending.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: credential.id,
        publicKey: credential.publicKey,
        counter: credential.counter,
        transports: credential.transports,
      },
      requireUserVerification: true,
    });

    if (!verification.verified) {
      throw new Error("패스키 검증에 실패했습니다.");
    }

    credential.counter = verification.authenticationInfo.newCounter;

    // 이미 사용한 challenge를 지워 재전송을 막는다.
    delete req.session.authentication;
    req.session.userId = user.id;

    res.json({
      verified: true,
      username: user.username,
    });
  } catch (error) {
    res.status(400).json({
      error: error.message || "로그인에 실패했습니다.",
    });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

/* 로그인한 사용자에게만 전달되는 자료 */

app.get("/api/private-profile", requireLogin, (req, res) => {
  res.json({
    studyMemo: "웹 인증과 네트워크 보안 기초를 공부하고 있습니다.",
    project: "패스키 기반 자기소개 웹사이트",
    goal: "보안과 게임 개발을 연결하는 프로젝트를 만들고 싶습니다.",
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});

app.get("/api/passkeys", requireLogin, (req, res) => {
  const user = [...users.values()].find(
    (item) => item.id === req.session.userId,
  );

  const passkeys = user.credentials.map((credential, index) => ({
    id: credential.id,
    name: `패스키 ${index + 1}`,
    createdAt: credential.createdAt,
  }));

  res.json(passkeys);
});

app.delete("/api/passkeys/:credentialId", requireLogin, (req, res) => {
  const user = [...users.values()].find(
    (item) => item.id === req.session.userId,
  );

  const index = user.credentials.findIndex(
    (credential) => credential.id === req.params.credentialId,
  );

  if (index === -1) {
    return res.status(404).json({
      error: "해당 패스키를 찾지 못했습니다.",
    });
  }

  user.credentials.splice(index, 1);

  if (user.credentials.length === 0) {
    return req.session.destroy(() => {
      res.json({
        message: "마지막 패스키를 삭제했습니다. 로그아웃됩니다.",
        remaining: 0,
      });
    });
  }

  res.json({
    message: "패스키를 삭제했습니다.",
    remaining: user.credentials.length,
  });
});
