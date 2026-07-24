// Thin client for the BFF. The browser holds no tokens - the session cookie is sent
// automatically. For state-changing requests we echo the CSRF cookie back in a header.

function readCookie(name) {
  return document.cookie
    .split('; ')
    .find((row) => row.startsWith(`${name}=`))
    ?.split('=')[1];
}

export async function getJson(path) {
  const response = await fetch(path, {
    headers: { Accept: 'application/json' },
    credentials: 'same-origin',
  });
  if (response.status === 401) {
    return { unauthorized: true };
  }
  if (!response.ok) {
    throw new Error(`Request to ${path} failed with ${response.status}`);
  }
  return { data: await response.json() };
}

// Login and logout are full-page navigations so the browser follows the OAuth redirects.
export function login() {
  window.location.assign('/oauth2/authorization/idp');
}

export function logout() {
  const token = readCookie('XSRF-TOKEN');
  const form = document.createElement('form');
  form.method = 'POST';
  form.action = '/logout';

  if (token) {
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = '_csrf';
    input.value = decodeURIComponent(token);
    form.appendChild(input);
  }

  document.body.appendChild(form);
  form.submit();
}
