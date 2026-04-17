const state = {
  activeUser: null,
};

const usernameEl = document.getElementById('username');
const passwordEl = document.getElementById('password');
const authStatusEl = document.getElementById('auth-status');
const conversationListEl = document.getElementById('conversation-list');
const messagesEl = document.getElementById('messages');
const activeChatEl = document.getElementById('active-chat');

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    ...options,
  });
  return response.json();
}

function setStatus(text) {
  authStatusEl.textContent = text;
}

async function refreshConversations() {
  const data = await api('/conversations');
  conversationListEl.innerHTML = '';

  if (data.status !== 'success') {
    return;
  }

  data.conversations.forEach((username) => {
    const li = document.createElement('li');
    li.textContent = username;
    if (state.activeUser === username) {
      li.classList.add('active');
    }

    li.onclick = async () => {
      state.activeUser = username;
      activeChatEl.textContent = `Chat with ${username}`;
      await refreshConversations();
      await refreshMessages();
    };

    conversationListEl.appendChild(li);
  });
}

async function refreshMessages() {
  messagesEl.innerHTML = '';

  if (!state.activeUser) {
    return;
  }

  const data = await api('/get_messages', {
    method: 'POST',
    body: JSON.stringify({ username: state.activeUser }),
  });

  if (data.status !== 'success') {
    return;
  }

  data.messages.forEach((msg) => {
    const div = document.createElement('div');
    div.className = 'message';
    div.textContent = `${msg.sender}: ${msg.message}`;
    messagesEl.appendChild(div);
  });
}

document.getElementById('signup-btn').onclick = async () => {
  const data = await api('/signup', {
    method: 'POST',
    body: JSON.stringify({
      username: usernameEl.value,
      password: passwordEl.value,
      public_key: 'web-client-placeholder-public-key'
    }),
  });
  setStatus(data.message || data.status);
};

document.getElementById('login-btn').onclick = async () => {
  const data = await api('/login', {
    method: 'POST',
    body: JSON.stringify({
      username: usernameEl.value,
      password: passwordEl.value,
    }),
  });
  setStatus(data.message || data.status);
  await refreshConversations();
};

document.getElementById('logout-btn').onclick = async () => {
  const data = await api('/logout');
  setStatus(data.message || 'Logged out');
  state.activeUser = null;
  activeChatEl.textContent = 'No active chat selected.';
  messagesEl.innerHTML = '';
  conversationListEl.innerHTML = '';
};

document.getElementById('start-chat-btn').onclick = async () => {
  const target = document.getElementById('new-chat-user').value;

  const data = await api('/start_chat', {
    method: 'POST',
    body: JSON.stringify({
      username: target,
      aes_key_user1: 'encrypted_key_for_me',
      aes_key_user2: 'encrypted_key_for_them'
    }),
  });

  setStatus(data.message || data.status);
  await refreshConversations();
};

document.getElementById('send-btn').onclick = async () => {
  if (!state.activeUser) return;

  const text = document.getElementById('message-input').value;
  const data = await api('/send_message', {
    method: 'POST',
    body: JSON.stringify({ username: state.activeUser, message: text }),
  });

  setStatus(data.message || data.status);
  document.getElementById('message-input').value = '';
  await refreshMessages();
};

document.getElementById('refresh-btn').onclick = async () => {
  await refreshConversations();
  await refreshMessages();
};
