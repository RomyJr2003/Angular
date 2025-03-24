import { Injectable } from '@angular/core';
import { HttpRequest, HttpHandler, HttpEvent, HttpInterceptor, HTTP_INTERCEPTORS, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';

const accountKey = 'fake-backend-accounts';
let accounts = JSON.parse(localStorage.getItem(accountKey)!) || [];

@Injectable()
export class FakeBackendInterceptor implements HttpInterceptor {
    intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
        const { url, method, headers, body } = request;

        return handleRoute();
        }

        function handleRoute() {
        switch (true) {
            case url.endsWith('/accounts/authenticate') && method === 'POST':
                return authenticate();
            case url.endsWith('/accounts/refresh-token') && method === 'POST':
                return refreshToken();
            case url.endsWith('/accounts/revoke-token') && method === 'POST':
                return revokeToken();
            case url.endsWith('/accounts/register') && method === 'POST':
                return register();
            case url.endsWith('/accounts/verify-email') && method === 'POST':
                return verifyEmail();
            case url.endsWith('/accounts/forgot-password') && method === 'POST':
                return forgotPassword();
            case url.endsWith('/accounts/validate-reset-token') && method === 'POST':
                return validateResetToken();
            case url.endsWith('/accounts/reset-password') && method === 'POST':
                return resetPassword();
            case url.endsWith('/accounts') && method === 'GET':
                return getAccounts();
            case url.match(/\/accounts\/\d+$/) && method === 'GET':
                return getAccountById();
            case url.endsWith('/accounts') && method === 'POST':
                return createAccount();
            case url.match(/\/accounts\/\d+$/) && method === 'PUT':
                return updateAccount();
            case url.match(/\/accounts\/\d+$/) && method === 'DELETE':
                return deleteAccount();
            default:
                return next.handle(request);
        }

        function authenticate() {
        const { email, password } = body;
        const account = accounts.find(x => x.email === email && x.password === password && x.isVerified);

        if (!account) return error('Email or password is incorrect');

        account.refreshTokens.push(generateRefreshToken());
        localStorage.setItem(accountKey, JSON.stringify(accounts));

        return ok({
        ...basicDetails(account),
        jwtToken: generateJwtToken(account)
        });
        }

        function refreshToken() {
        const refreshToken = getRefreshToken();

        if (!refreshToken) return unauthorized();

        const account = accounts.find(x => x.refreshTokens.includes(refreshToken));

        if (!account) return unauthorized();

        account.refreshTokens = account.refreshTokens.filter(x => x !== refreshToken);
        account.refreshTokens.push(generateRefreshToken());
        localStorage.setItem(accountKey, JSON.stringify(accounts));

        return ok({
            ...basicDetails(account),
            jwtToken: generateJwtToken(account)
        });
        }

        function revokeToken() {
        if (!isAuthenticated()) return unauthorized();

        const refreshToken = getRefreshToken();
        const account = accounts.find(x => x.refreshTokens.includes(refreshToken));

        if (!account) return unauthorized();

        account.refreshTokens = account.refreshTokens.filter(x => x !== refreshToken);
        localStorage.setItem(accountKey, JSON.stringify(accounts));

        return ok();
        }
        function register() {
        const account = body;

        if (accounts.find(x => x.email === account.email)) {
            setTimeout(() => {
                alert(`
                    <h4>Email Already Registered</h4>
                    <p>Your email ${account.email} is already registered.</p>
                    <p>If you forgot your password please visit the 
                    <a href="${location.origin}/account/forgot-password">forgot password</a> page.</p>
                    <p>The fake backend displayed this "email" so you can test without an API. 
                    A real backend would send a real email.</p>
                `);
            }, 1000);
            return ok();
        }

        account.id = new Date().getTime().toString();
        account.verified = false;
        account.refreshTokens = [];
        accounts.push(account);
        localStorage.setItem(accountKey, JSON.stringify(accounts));

        return ok();
        }

        function setTimeoutEmail() {
        setTimeout(() => {
            alert(`
                <h4>Verification Email</h4>
                <p>Please click the link below to verify your email address:</p>
                <p><a href="${location.origin}/account/verify-email?token=${account.verificationToken}">
                Verify Email</a></p>
                <p>The fake backend displayed this "email" so you can test without an API. 
                A real backend would send a real email.</p>
            `);
        }, 1000);

        return ok();
        }

        function verifyEmail() {
        const { token } = body;
        const account = accounts.find(x => x.verificationToken === token);

        if (!account) return error('Verification failed');

        account.verified = true;
        localStorage.setItem(accountKey, JSON.stringify(accounts));

        return ok();
        }
        function forgotPassword() {
        const { email } = body;
        const account = accounts.find(x => x.email === email);

        // always return aok response to prevent email enumeration
        if (!account) return ok();

        // create reset token that expires after 24 hours
        account.resetToken = new Date().getTime().toString();
        account.resetTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
        localStorage.setItem(accountsKey, JSON.stringify(accounts));

        // display password reset email in alert
        setTimeout(() => {
            const resetUrl = `${location.origin}/account/reset-password?token=${account.resetToken}`;
            alertService.info(`
                <h4>Check Email</h4>
                <p>Please check the below link to reset your password, the Link will be valid for 1 day:</p>
                <p><a href="${resetUrl}">${resetUrl}</a></p>
                <div><strong>NOTE:</strong> The fake backend displayed this "email" so you can test without an API. A real backend would send a real email.</div>
            `, { autoClose: false });
        }, 1000);

        return ok();
        }

        function validateResetToken() {
        const { token } = body;
        const account = accounts.find(x =>
            x.resetToken === token &&
            new Date() < new Date(x.resetTokenExpires)
        );

        if (!account) return error('Invalid token');

        return ok();
        }

        function resetPassword() {
        const { token, password } = body;
        const account = accounts.find(x =>
            !!x.resetToken && x.resetToken === token &&
            new Date() < new Date(x.resetTokenExpires)
        );

        if (!account) return error('Invalid token');

        // update password and remove reset token
        account.password = password;
        account.isVerified = true;
        delete account.resetToken;
        delete account.resetTokenExpires;
        localStorage.setItem(accountsKey, JSON.stringify(accounts));

        return ok();
        }

        function getAccounts() {
        if (!isAuthenticated()) return unauthorized();
        return ok(accounts.map(x => basicDetails(x)));
        }

        function getAccountById() {
        if (!isAuthenticated()) return unauthorized();

        let account = accounts.find(x => x.id === idFromUrl());

        // user accounts can get own profile and admin accounts can get all profiles
        if (account.id !== currentAccount().id && !isAuthorized(Role.Admin)) {
            return unauthorized();
        }

        return ok(basicDetails(account));
        }

        function createAccount() {
        if (!isAuthorized(Role.Admin)) return unauthorized();

        const account = body;
        if (accounts.find(x => x.email === account.email)) {
            return error(`Email ${account.email} is already registered`);
        }

        // assign account id and a few other properties then save
        account.id = newAccountId();
        account.dateCreated = new Date().toISOString();
        account.isVerified = true;
        account.refreshTokens = [];
        delete account.confirmPassword;
        accounts.push(account);
        localStorage.setItem(accountsKey, JSON.stringify(accounts));

        return ok();
        }

        function updateAccount() {
        if (!isAuthenticated()) return unauthorized();

        let params = body;
        let account = accounts.find(x => x.id === idFromUrl());

        // user accounts can update own profile and admin accounts can update all profiles
        if (account.id !== currentAccount().id && !isAuthorized(Role.Admin)) {
            return unauthorized();
        }

        // only update password if included
        if (!params.password) {
            delete params.password;
            delete params.confirmPassword;
        }

        Object.assign(account, params);
        localStorage.setItem(accountsKey, JSON.stringify(accounts));

        return ok(basicDetails(account));
        }

        function deleteAccount() {
        if (!isAuthenticated()) return unauthorized();

        let account = accounts.find(x => x.id === idFromUrl());

        // user accounts can delete own account and admin accounts can delete any account
        if (account.id !== currentAccount().id && !isAuthorized(Role.Admin)) {
            return unauthorized();
        }

        // delete account then save
        accounts = accounts.filter(x => x.id !== idFromUrl());
        localStorage.setItem(accountsKey, JSON.stringify(accounts));
        return ok();
        }

        function error(message) {
        return response({ message }, { status: 400, body: { message } });
        }

        function unauthorized() {
        return response({ message: 'Unauthorized' }, { status: 401 });
        }

        function response(body, init) {
        return new Response(JSON.stringify(body), { ...init, headers: { 'Content-Type': 'application/json' } });
        }

        function isAuthenticated() {
        return !!currentAccount();
        }

        function isAuthorized(role) {
        const account = currentAccount();
        return account && account.role === role;
        }

        function newAccountId() {
        return accounts.length ? Math.max(...accounts.map(x => x.id)) + 1 : 1;
        }

        function currentAccount() {
        // check if jwt token is in auth header
        const authHeader = headers.get('Authorization');
        if (!authHeader.startsWith('Bearer fake-jwt-token')) return;

        // check if token is expired
        const jwtToken = JSON.parse(atob(authHeader.split('.')[1]));
        const tokenExpired = Date.now() > (jwtToken.exp * 1000);
        if (tokenExpired) return;

        const account = accounts.find(x => x.id === jwtToken.id);
        return account;
        }

        function generateJwtToken(account) {
        // create token that expires in 15 minutes
        const tokenPayload = {
            exp: Math.round(new Date(Date.now() + 15 * 60 * 1000).getTime() / 1000),
            id: account.id
        };

        return `fake-jwt-token.${btoa(JSON.stringify(tokenPayload))}`;
        }

        function generateRefreshToken() {
        const token = new Date().getTime().toString();

        // add token cookie that expires in 7 days
        const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toUTCString();
        document.cookie = `fakeRefreshToken=${token}; expires=${expires}; path=/`;

        return token;
        }

        function getRefreshToken() {
        // get refresh token from cookie
        return document.cookie.split('; ').find(x => x.includes('fakeRefreshToken'))?.split('=')[1] || null;
        }
    }
}

export let fakeBackendProvider = {
    provide: HTTP_INTERCEPTORS,
    useClass: FakeBackendInterceptor,
    multi: true
};




