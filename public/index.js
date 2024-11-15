import React from 'react';

export default function LoginPage() {
  return (
    <>
      <head>
        <meta charSet="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Firebase Auth</title>
      </head>
      <body>
        <button>Sign in with Google</button>
        <script type="module" src="../src/main.js"></script>
      </body>
    </>
  );
}