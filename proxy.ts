import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { createHash, timingSafeEqual } from 'node:crypto';

const COOKIE_NAME = 'kfch_library_auth';

function tokenFor(password: string) {
  return createHash('sha256').update(password + ':KFCH-Stroke-Library').digest('hex');
}

function safeEqual(a: string, b: string) {
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}

function loginPage(message = '') {
  return new NextResponse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>KFCH Library Access</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f7f9;font-family:Arial,sans-serif;color:#17384b}.card{width:min(92vw,420px);background:#fff;padding:34px;border-radius:16px;box-shadow:0 12px 40px #1233;text-align:center}h1{font-size:22px;margin:0 0 8px}p{font-size:14px;color:#607785;margin:0 0 24px}input{width:100%;padding:13px;border:1px solid #cbd7de;border-radius:9px;font-size:16px;margin-bottom:12px}button{width:100%;padding:13px;border:0;border-radius:9px;background:#155b75;color:#fff;font-size:15px;font-weight:700;cursor:pointer}.err{color:#b42318;margin-top:12px;font-size:13px}</style></head><body><main class="card"><h1>KFCH Medical Electronic Library</h1><p>Authorized access only. Enter the site password to continue.</p><form method="POST" action="/__kfch_login"><input name="password" type="password" autocomplete="current-password" required autofocus placeholder="Password"><button type="submit">Access Library</button></form>${message ? `<div class="err">${message}</div>` : ''}</main></body></html>`, {
    status: 401,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'private, no-store, no-cache, must-revalidate'
    }
  });
}

export async function proxy(request: NextRequest) {
  const password = process.env.SITE_PASSWORD;
  if (!password) {
    return new NextResponse('Site protection is not configured.', { status: 503 });
  }

  if (request.nextUrl.pathname === '/__kfch_login' && request.method === 'POST') {
    const form = await request.formData();
    const entered = String(form.get('password') || '');
    if (!safeEqual(entered, password)) return loginPage('Incorrect password.');

    const response = NextResponse.redirect(new URL('/', request.url), 303);
    response.cookies.set(COOKIE_NAME, tokenFor(password), {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 28800
    });
    response.headers.set('cache-control', 'private, no-store');
    return response;
  }

  const cookie = request.cookies.get(COOKIE_NAME)?.value || '';
  const expected = tokenFor(password);
  if (cookie && safeEqual(cookie, expected)) {
    return NextResponse.next();
  }

  return loginPage();
}

export const config = {
  matcher: '/:path*'
};
