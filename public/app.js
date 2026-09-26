const status = document.querySelector("#status");
const usernameInput = document.querySelector("#username");
const registerButton = document.querySelector("#register-button");
const loginButton = document.querySelector("#login-button");
const privateButton = document.querySelector("#private-button");
const logoutButton = document.querySelector("#logout-button");
const listPasskeysButton = document.querySelector("#list-passkeys-button");
const privateContent = document.querySelector("#private-content");
const passkeyList = document.querySelector("#passkey-list");

function setStatus(message) {
  status.textContent = message;
}

async function request(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.error || "요청에 실패했습니다.");
  }

  return data;
}

registerButton.addEventListener("click", async () => {
  try {
    const username = usernameInput.value.trim();

    setStatus("패스키 등록 창을 여는 중입니다.");

    const optionsJSON = await request("/api/passkeys/register/options", {
      method: "POST",
      body: JSON.stringify({ username }),
    });

    const response = await SimpleWebAuthnBrowser.startRegistration({
      optionsJSON,
    });

    const result = await request("/api/passkeys/register/verify", {
      method: "POST",
      body: JSON.stringify(response),
    });

    setStatus(
      `${result.username}님이 패스키 ${result.passkeyCount}개를 등록했습니다.`,
    );
  } catch (error) {
    setStatus(`등록 실패: ${error.message}`);
  }
});

loginButton.addEventListener("click", async () => {
  try {
    setStatus("패스키 인증 창을 여는 중입니다.");

    const optionsJSON = await request("/api/passkeys/login/options", {
      method: "POST",
    });

    const response = await SimpleWebAuthnBrowser.startAuthentication({
      optionsJSON,
    });

    const result = await request("/api/passkeys/login/verify", {
      method: "POST",
      body: JSON.stringify(response),
    });

    setStatus(`${result.username}님이 로그인했습니다.`);
  } catch (error) {
    setStatus(`로그인 실패: ${error.message}`);
  }
});

privateButton.addEventListener("click", async () => {
  try {
    const data = await request("/api/private-profile");

    privateContent.replaceChildren();

    Object.entries(data).forEach(([key, value]) => {
      const paragraph = document.createElement("p");
      paragraph.textContent = `${key}: ${value}`;
      privateContent.appendChild(paragraph);
    });

    setStatus("인증된 사용자에게만 비공개 자료를 표시했습니다.");
  } catch (error) {
    privateContent.textContent = "";
    setStatus(`비공개 자료 접근 실패: ${error.message}`);
  }
});

logoutButton.addEventListener("click", async () => {
  try {
    await request("/api/logout", { method: "POST" });
    privateContent.textContent = "";
    passkeyList.textContent = "";
    setStatus("로그아웃했습니다.");
  } catch (error) {
    setStatus(`로그아웃 실패: ${error.message}`);
  }
});

async function showPasskeys() {
  const passkeys = await request("/api/passkeys");

  passkeyList.replaceChildren();

  const title = document.createElement("h3");
  title.textContent = `등록된 패스키: ${passkeys.length}개`;
  passkeyList.appendChild(title);

  passkeys.forEach((passkey) => {
    const row = document.createElement("p");
    row.textContent = `${passkey.name} / ${new Date(passkey.createdAt).toLocaleString("ko-KR")} `;

    const deleteButton = document.createElement("button");
    deleteButton.textContent = "삭제";

    deleteButton.addEventListener("click", async () => {
      const result = await request(
        `/api/passkeys/${encodeURIComponent(passkey.id)}`,
        { method: "DELETE" },
      );

      setStatus(result.message);
      passkeyList.textContent = "";

      if (result.remaining > 0) {
        await showPasskeys();
      }
    });

    row.appendChild(deleteButton);
    passkeyList.appendChild(row);
  });
}

listPasskeysButton.addEventListener("click", async () => {
  try {
    await showPasskeys();
  } catch (error) {
    setStatus(`패스키 목록 실패: ${error.message}`);
  }
});
