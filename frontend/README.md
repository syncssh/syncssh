# SyncSSH frontend

The dashboard is a React application built with Vite and Tailwind CSS.

```bash
npm ci
npm run dev
```

The development server proxies API and account requests to the Django backend.
Set `VITE_API_PROXY` to override the default `http://localhost:8000` target.

Before submitting changes, run:

```bash
npm run lint
npm run build
```
