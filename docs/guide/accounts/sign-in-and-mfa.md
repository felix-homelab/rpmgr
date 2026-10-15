# Sign-in and two-factor authentication

This page is for everyone who signs in to rpmgr's web UI. It covers the first account of a new
installation, signing in and out, your sessions, an authenticator app as a second factor with its
recovery codes, confirming your identity again for sensitive actions (step-up), and resetting a
password. Accounts are local to the controller: an e-mail address and a password, with an optional
authenticator. Single sign-on and passkeys are not available yet; they are planned for Phase 2
([05](../../05-features.md#identity-and-access)).

## The first user

A new controller has no users. Its initialisation prints a one-time link that creates the first
one, who becomes the Owner of the first organisation and the Instance Admin.

### Before you start

- The controller or all-in-one is initialised and running ([rpmgr setup](../install/setup.md)).
- You have the first-user link that `rpmgr setup`, `rpmgr controller init` or
  `rpmgr all-in-one init` printed: `<public URL>/setup#<token>`.

### Steps

1. Open the link in a browser.
2. On **Create the first account**, enter your **E-mail address**, **Your name**, a **New
   password** and **Repeat the new password**.
3. Press **Create the account**. You are signed in and see the overview.

The link works once, for a limited time, and only while no user exists
([04](../../04-security.md#human-authentication-and-sessions)). If it expired before you used it,
make a new one on the controller host:

```sh
sudo rpmgr user reset-password
```

Without `--email` and before the first user exists, the command prints a new first-user link
([Public pages](../web-ui/public-pages.md#create-the-first-account)).

## Sign in

1. Open the controller's public URL. Without a session, the web UI shows **Sign in to rpmgr**.
2. Enter your **E-mail address** and **Password**, and press **Sign in**.
3. If you have an authenticator, enter the **Authenticator code or recovery code** and press
   **Sign in** again.

A wrong address and a wrong password give the same answer, so the page reveals no accounts.
After several failures in a row, each further attempt for the account waits longer, and the page
says how many seconds to wait; too many attempts from one address are refused for a while
([04](../../04-security.md#human-authentication-and-sessions)). An attacker cannot lock you out this
way: a correct password still works once the wait is over.

The command line does not sign in with a password: it uses a personal API token
([API tokens and the command line](api-tokens-and-cli.md)).

## Sessions

Signing in starts a session in that browser, held in a cookie that scripts in the page cannot
read. A session ends when you sign out, after a period without activity, or at the latest after a
fixed time ([04](../../04-security.md#human-authentication-and-sessions)); the web UI then sends
you to sign in again and back to where you were.

- **Sign out:** the user menu in the top bar, **Sign out**.
- **See and end your sessions:** **Your account**, card **Sessions**. Each session shows its
  browser, address and last activity; **End…** and **End it** sign another browser out
  ([Account](../web-ui/account.md#sessions)).
- **Changing your password or your authenticator, or making new recovery codes, ends all your
  other sessions.** The browser that made the change stays signed in. A password reset ends every
  session. None of these ends your API tokens; revoke a token yourself if it may have leaked
  ([API tokens](api-tokens-and-cli.md#list-and-revoke-tokens)).

## Set up an authenticator

An authenticator app on your phone, such as any app that reads `otpauth://` QR codes, adds a
second factor: signing in then needs a code from the app as well as your password.

### Before you start

- An authenticator app.
- A safe place for the recovery codes, such as a password manager.

### Steps

1. Open **Your account** from the user menu.
2. In **Two-factor authentication**, press **Set up an authenticator**. Confirm your identity if
   the step-up dialog asks ([Step-up](#step-up-confirming-it-is-you)).
3. Scan the QR code with the app, or type the key shown under it into the app.
4. Enter the code the app shows into **Code from the app** and press **Turn on**.
5. The card shows your **Recovery codes**, once. Save them, then press **I have saved them**.

Your other sessions end. From now on, signing in and every step-up ask for a code from the app.

![Setting up an authenticator on the account page](../images/web/account-authenticator.png)

## Recovery codes

Each recovery code works once in place of a code from the app, at sign-in and at a step-up. When
you type one, upper or lower case and dashes do not matter.

- **New codes:** **Your account**, **New recovery codes**, after a step-up. The old codes stop
  working, the new ones are shown once, and your other sessions end; this browser stays signed
  in. Do this when you have used most of them, or think someone has seen them. In that case, also
  check your API tokens and revoke any you did not make: new codes do not end them
  ([API tokens](api-tokens-and-cli.md#list-and-revoke-tokens)).
- **Lost phone:** sign in with a recovery code, remove the authenticator and set up a new one.
- **Lost phone and codes:** this version has no way for an administrator to remove another user's
  authenticator, so the account cannot sign in again. Keep the codes safe.

## Remove the authenticator

**Your account**, **Remove the authenticator…**, then **Remove it**, after a step-up. Your
password alone then signs you in, and your other sessions end. You can then set up a new one.

## When your organisation requires it

An Owner can require every member to sign in with a second factor: **Settings**, **Every member
must sign in with a second factor** ([Settings](../web-ui/settings.md#organisation-settings)).
Turning it on needs a step-up.

- A member who signed in without a second factor is then refused in that organisation: the web UI
  takes them to **Your account** with the message `An organisation you belong to requires
  two-factor authentication. Set up an authenticator to continue.` Setting one up is always
  possible.
- After setting it up, sign out and sign in again with a code from the app to work in the
  organisation; a step-up with a code counts as well.
- The policy accepts an API token only if the session that made it was signed in with a second
  factor ([04](../../04-security.md#human-authentication-and-sessions)).

## Step-up: confirming it is you

Some actions need a fresh confirmation of your identity, even within a session: making an
enrollment or gateway token, making an API token, changing your authenticator or recovery codes,
granting the Admin or Owner role or inviting someone with it, changing the organisation's
second-factor requirement, making a password reset link for someone, marking a domain as trusted,
rotating the CA's intermediate, and resuming tokens or confirming members after a restore
([04](../../04-security.md#human-authentication-and-sessions)).

- **In the web UI** the **Confirm it is you** dialog opens when such an action needs it. Enter your
  password, or, if you have an authenticator, a code from it or a recovery code, and press
  **Confirm**. The action then goes ahead
  ([The step-up dialog](../web-ui/README.md#the-step-up-dialog)).
- **On the command line** a command that needs a step-up asks on the terminal for the code from
  your authenticator or a recovery code, or your password if you have no second factor, then runs
  ([D63](../../14-open-decisions.md#engineering)).

The confirmation lasts a few minutes ([04](../../04-security.md#human-authentication-and-sessions)),
so several such actions in a row ask once. A step-up of the web UI covers that browser's session
only, and a step-up of the command line covers that API token only. Failed step-ups count like
failed sign-ins.

## Forgot your password

How you get a new password depends on whether the controller can send e-mail, which is the
Instance Admin's **Mail relay** setting ([Settings](../web-ui/settings.md#instance-settings)).

### With a mail relay

1. On the sign-in page, press **Forgot your password?**.
2. Enter your **E-mail address** and press **Send a reset link**. The page gives the same answer
   whether an account uses the address or not.
3. Open the link in the e-mail. On **Set a new password**, enter the new password twice and press
   **Set the password**.
4. Sign in with the new password. All your sessions have ended.

The link works once, for a limited time
([04](../../04-security.md#human-authentication-and-sessions)). A reset sets the password only:
an authenticator stays, and signing in still asks for its code.

### Without a mail relay

On **Reset your password**, the page that **Forgot your password?** opens, **Send a reset link**
answers that the controller cannot send e-mail. Ask for a reset link instead:

- **On the controller host**, whoever administers it runs, as root or the rpmgr service user:

  ```sh
  sudo rpmgr user reset-password --email ada@example.com
  ```

  It prints a one-time link to pass on. Such local administration needs no account and is audited
  ([04](../../04-security.md#roles)).
- **Through the API**, an Owner or Admin can make a link for a member of their organisation (an
  Admin not for an Owner), and the Instance Admin for any user, with
  `UserService.CreatePasswordResetLink` ([API](../reference/api.md)). It needs a signed-in browser
  session and a step-up; it refuses an API token. The web UI and the command line have no button
  or command for it in this version.

The person then opens the link and sets a password as in step 3 above.

## Change your password

**Your account**, card **Password**: enter the **Current password**, the **New password** twice,
and press **Change the password** ([Account](../web-ui/account.md#password)). Your other sessions
end; this browser stays signed in. Wrong current passwords count like failed step-ups.

## Troubleshooting

- **`Too many attempts`:** wait the seconds the page names, then try again with the right password.
- **The code is refused:** check that the phone's clock is right, and use the next code; a code
  works once.
- **You are sent back to Your account after signing in:** your organisation requires a second
  factor; set one up ([above](#when-your-organisation-requires-it)).
- **More:** [Troubleshooting](../operations/troubleshooting.md).
