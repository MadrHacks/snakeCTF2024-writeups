# Affekot [_snakeCTF 2024 Quals_]

**Category**: web

## Description

I really want to buy the flag, but it's out of stock!

I heard that the admin took the last one...

## Solution

### Step 1: The Frontend Analysis

The first step involves inspecting the frontend code of the web application. Although direct access to the source code is not provided, a key file that can typically be found in most Next.js applications, `_buildManifest.js`, can be analysed. This file discloses the paths to all built pages, excluding API routes.

By examining this file, it is possible to identify hidden routes, such as `/dev`, `/dev/signin`, and `/dev/signup`. These routes are essential for progressing in the challenge.

### Step 2: Exploiting the Admin Login

The vulnerability lies in the `/dev/signin` route. When users log in via this page, they are automatically authenticated as the "admin" user for all `/dev/*` pages. The flaw stems from the use of the same JSON Web Token (JWT) secret key for both development and production environments.

This flaw can be exploited by modifying the token to set the cookie path to `/`, which provides admin-level access to the entire website, not only the `/dev/*` pages.

### Step 3: Retrieving the Flag from the Orders Page

With admin access granted, the `/orders` page can be accessed. The flag will be displayed within a `<code>` element.

[Here](./attachments/solve.py) is the solver code.
