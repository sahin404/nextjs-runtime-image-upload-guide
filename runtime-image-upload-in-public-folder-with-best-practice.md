# Runtime Image Upload in the Public Folder — With Best Practices

A complete, copy-paste-able guide for accepting image uploads at runtime and serving them reliably in a Next.js (App Router) project. It covers the naive "write to `public/` and link it" approach, explains every drawback of that approach, and then shows the proper **write + serve-via-API** pattern.

## Table of Contents

1. [Overview](#1-overview)
2. [The Traditional (Naive) Approach](#2-the-traditional-naive-approach)
3. [Drawbacks of the Traditional Approach](#3-drawbacks-of-the-traditional-approach)
4. [Recommended Pattern: Write + Serve via API Routes](#4-recommended-pattern-write--serve-via-api-routes)
5. [Why Serving via API Works](#5-why-serving-via-api-works)
6. [Displaying Uploaded Images](#6-displaying-uploaded-images)
7. [Production Hardening Checklist](#7-production-hardening-checklist)
8. [Flow Diagram](#8-flow-diagram)
9. [File Reference Map](#9-file-reference-map)

---

## 1. Overview

Any app that lets users upload content (blog thumbnails, product photos, avatars, project images) faces two problems:

1. **Writing the bytes** — receiving the file and persisting it somewhere at runtime.
2. **Serving the bytes** — returning that file to the browser so it actually renders, with correct headers and without breaking security or caching.

Most tutorials stop at the *naive* version of problem 1 and ignore problem 2. That version works in local development but breaks in production.

This guide uses a simple running example: an app where users upload an image for a blog post. The pattern generalizes to *any* image-backed entity (products, projects, categories, avatars, etc.) by swapping the `<folder>` names.

---

## 2. The Traditional (Naive) Approach

```ts
// src/app/api/upload/route.ts
import { writeFile, mkdir } from "fs/promises";
import path from "path";
import { NextResponse } from "next/server";

export async function POST(request: Request) {
  const formData = await request.formData();
  const file = formData.get("file") as File;

  // filename comes straight from the client
  const fileName = file.name;
  const uploadDir = path.join(process.cwd(), "public", "uploads", "blog");

  await mkdir(uploadDir, { recursive: true });
  const buffer = Buffer.from(await file.arrayBuffer());
  await writeFile(path.join(uploadDir, fileName), buffer);

  return NextResponse.json({ url: `/uploads/blog/${fileName}` }, { status: 201 });
}
```

Then in a component:

```tsx
<img src={`/uploads/blog/${fileName}`} alt="post" />
```

This "works" locally: the file lands in `public/uploads/blog/` and Next.js statically serves the direct URL. But it hides half a dozen serious problems.

---

## 3. Drawbacks of the Traditional Approach

### 3.1 Filename Collisions (silent data loss)

The file is saved using the client's original name. Two users uploading `photo.jpg` — or one user uploading it twice — overwrites the previous file with the same name. No error is raised; the old image silently disappears.

```ts
const fileName = file.name; // photo.jpg → photo.jpg → overwritten!
```

### 3.2 No Control Over Response Headers

Next.js serves files inside `public/` as static assets with its own default headers:

- You cannot set `Cache-Control: public, max-age=31536000, immutable`.
- You cannot override `Content-Type` when the extension is missing or wrong.
- You cannot inject security headers, ETags, or a `Content-Disposition`.

Since uploaded filenames are unique per upload, an **immutable one-year cache** is exactly the right strategy — but with direct public links you have no way to apply it, so browsers revalidate every image on every page load.

### 3.3 Path Traversal

Filenames come from the client. A malicious request can send a filename like:

```
../../.env        →  overwrites your env file
../../../app/page.tsx  →  overwrites source code
```

Because the naive code joins the raw name straight into the write path, an attacker can **write files anywhere the process can write** — outside `public/` entirely. This is the most dangerous flaw in the naive approach.

### 3.4 No Auth or Rate Limiting

The naive route accepts uploads from anyone, any time. Unauthenticated users can fill your disk with junk files and spam the endpoint. If a user upload is a data-drive feature (e.g., your authenticated dashboard is the only place that should write), the upload route must be gated the same way as the rest of the CRUD API.

### 3.5 Ephemeral / Read-Only Filesystem on Serverless (the production killer)

On serverless platforms (Vercel, Netlify, Cloudflare Pages, AWS Lambda):

- The filesystem is **read-only** or otherwise not writable — `writeFile` into `public/` throws at runtime.
- Even when writable, the filesystem is **ephemeral**: every new deployment spins up fresh instances with a clean filesystem. Whatever you uploaded is gone after the next deploy.
- Each serverless instance has its own local disk — a file written on one instance is invisible to the next request that lands on a different instance.

The naive code passes `npm run dev` and fails immediately in production. This is the single biggest reason to avoid the naive pattern.

### 3.6 Not Registered in the Build Manifest

`next build` snapshots everything that will exist in production: it walks `public/` and registers every file in the build output (`.next` manifests / the platform's deploy artifact). Production then serves **that build-time snapshot** — not "whatever happens to exist on disk at request time".

A file written into `public/` at runtime:

- **`next dev`** — works. The dev server reads the live filesystem.
- **`next build` + deployed** — the entry was never registered, so the serving layer returns `404` for its URL. Serverless platforms can't even write the file in the first place (see 3.5).
- **Self-hosted `next start`** — may serve it today from the live disk, but the next redeploy starts from a fresh build (file gone), and it's invisible to CDN edge caching.

So the naive pattern "works in dev" and 404s in production — the manifest is frozen at build time.

This is exactly why the serving route in section 4.3 exists: it reads the file on demand with `fs.readFile()`, completely bypassing the static manifest. That works wherever a persistent writable filesystem exists (self-hosted VM/container), but on serverless it still ends up empty — which is why section 7 pushes object storage as the real production answer.

### 3.7 Orphaned Files Accumulate

Direct-link uploads get referenced only by whatever URL happened to be saved into the database. When a user updates or deletes their post, nobody tells the filesystem to remove the old file. `public/uploads/` fills up with thousands of dead files, slowly driving up repository size, build time, and storage costs.

### 3.8 MIME Spoofing + SVG XSS

The naive route trusts `file.type` — which is just the client *saying* "this is an image". An attacker can send:

- An HTML file labeled `image/png` → served as `image/png` by a naive route, or worse.
- An **SVG** with embedded `<script>`/`<foreignObject>` payloads → stored XSS when a victim opens the image URL directly in a new tab.

The trust boundary must sit on the **server** (magic-byte sniffing for real JPEG/PNG/WebP), not on the client-declared MIME string.

### 3.9 No Server-Side Size Limits

A naive route stores whatever the client sends. There is no `MAX_FILE_SIZE` check server-side, so a single 200 MB "image" is written to disk happily. Combined with no rate limiting (3.4), this is a trivial disk/bandwidth DoS vector.

---

## 4. Recommended Pattern: Write + Serve via API Routes

The fix is to move all file access behind **API route handlers** so that you control naming, validation, headers, and security — and nothing in the filesystem is reachable by guessing a URL.

The pattern has three pieces:

1. **Upload route** — validates and writes the file, returns an API URL.
2. **Client helper** — builds `FormData`, calls the upload route, returns the URL to store in the DB.
3. **Serving routes** — read the file from disk and stream it back with correct headers.

### 4.1 Upload Route — `POST /api/upload`

`src/app/api/upload/route.ts`

```ts
import path from "path";
import crypto from "crypto";
import { mkdir, writeFile } from "fs/promises";
import { NextResponse } from "next/server";

function getImageExtension(file: File) {
  const byName = path.extname(file.name).toLowerCase();
  if (byName) return byName;

  switch (file.type) {
    case "image/jpeg": return ".jpg";
    case "image/png":  return ".png";
    case "image/webp": return ".webp";
    case "image/gif":  return ".gif";
    case "image/avif": return ".avif";
    case "image/svg+xml": return ".svg";
    default: return "";
  }
}

export async function POST(request: Request) {
  try {
    const formData = await request.formData();
    const file = formData.get("file");

    if (!(file instanceof File)) {
      return NextResponse.json(
        { success: false, message: "Image file is required." },
        { status: 400 }
      );
    }

    if (!file.type.startsWith("image/")) {
      return NextResponse.json(
        { success: false, message: "Only image files are allowed." },
        { status: 400 }
      );
    }

    // "folder" keeps uploads organized per entity and defines the API URL shape
    const folder = (formData.get("folder") as string) || "blog";
    const extension = getImageExtension(file);

    // Collision-safe: Date.now() + a random UUID means two "photo.jpg"
    // uploads never collide, and the filename is always unique + hard to guess.
    const fileName = `${Date.now()}-${crypto.randomUUID()}${extension}`;
    const uploadDir = path.join(process.cwd(), "public", "images", folder);

    await mkdir(uploadDir, { recursive: true });
    const buffer = Buffer.from(await file.arrayBuffer());
    await writeFile(path.join(uploadDir, fileName), buffer);

    // Return an API URL, NOT the direct public path.
    const apiPrefix = `/api/${folder}/images/`;
    return NextResponse.json(
      {
        success: true,
        message: "Image uploaded successfully",
        data: { url: `${apiPrefix}${fileName}` },
      },
      { status: 201 }
    );
  } catch (error) {
    console.error("Upload error:", error);
    return NextResponse.json(
      { success: false, message: "Internal server error" },
      { status: 500 }
    );
  }
}
```

**Key behaviors:**

- **Whitelist by MIME**: only `image/*` is accepted (`400` otherwise).
- **Never trust the client's name**: the stored filename is `${Date.now()}-${crypto.randomUUID()}${ext}` — collision-proof and unguessable.
- **`mkdir({ recursive: true })`**: creates `public/images/<folder>/` on first use, no manual setup.
- **Returns an API URL** (`/api/blog/images/<fileName>`), not `/images/...` — this is the contract change that unlocks all the fixes in section 5.
- **`<folder>` is the extensibility knob**: `products`, `projects`, `blog`, `categories`, avatars — each becomes its own API namespace.

> The server URL will usually be stored in a database (e.g., a `thumbnailImage` column) so pages know what to render. Cloud storage is covered in section 7.

### 4.2 Client Helper — `uploadImage()`

`src/lib/upload.ts`

```ts
export async function uploadImage(file: File, folder?: string) {
  const formData = new FormData();
  formData.append("file", file);
  if (folder) formData.append("folder", folder);

  const response = await fetch("/api/upload", {
    method: "POST",
    body: formData,
  });

  const data = await response.json();

  if (!response.ok || !data?.success) {
    throw new Error(data?.message || "Image upload failed");
  }

  return String(data.data.url);
}
```

Use it from any composer/modal. The returned string is ready to persist in the database or embed in rich-text HTML:

```tsx
const handleFilePicked = async (e: React.ChangeEvent<HTMLInputElement>) => {
  const file = e.target.files?.[0];
  if (!file) return;

  const url = await uploadImage(file, "blog"); // "/api/blog/images/1710-<uuid>.jpg"
  // save url to your entity (Prisma column, content HTML, etc.)
};
```

### 4.3 Serving Route — `GET /api/<type>/images/[filename]`

One identical route per upload folder. This is the inverse of the upload route: instead of trusting a public path, it reads the file from disk under your control.

`src/app/api/blog/images/[filename]/route.ts`

```ts
import path from "path";
import { readFile } from "fs/promises";
import { NextResponse } from "next/server";

function getContentType(filename: string) {
  const ext = path.extname(filename).toLowerCase();
  switch (ext) {
    case ".jpg":
    case ".jpeg": return "image/jpeg";
    case ".png":  return "image/png";
    case ".webp": return "image/webp";
    case ".gif":  return "image/gif";
    case ".avif": return "image/avif";
    case ".svg":  return "image/svg+xml";
    default:      return "application/octet-stream";
  }
}

export async function GET(
  _request: Request,
  context: { params: Promise<{ filename: string }> }
) {
  try {
    const { filename } = await context.params;

    // Path-traversal guard: strip any directory segments before joining.
    const safeFilename = path.basename(filename);
    const filePath = path.join(process.cwd(), "public", "images", "blog", safeFilename);

    const file = await readFile(filePath);

    return new NextResponse(file, {
      headers: {
        "Content-Type": getContentType(safeFilename),
        "Cache-Control": "public, max-age=31536000, immutable",
      },
    });
  } catch {
    return NextResponse.json(
      { success: false, message: "Image not found" },
      { status: 404 }
    );
  }
}
```

> **Next.js 16 note:** dynamic route handler params are a `Promise` and **must be awaited** (`const { filename } = await context.params`). Older tutorials that destructure `params` directly are outdated for this version.

---

## 5. Why Serving via API Works

The API serving route is where the naive approach's weaknesses get fixed:

| Problem | Naive direct access | API route pattern |
|---|---|---|
| Collisions | Client name overwrites | `Date.now()-UUID` unique name |
| Headers | None controllable | `Cache-Control: public, max-age=31536000, immutable` + exact `Content-Type` |
| Path traversal | Raw name joined | `path.basename()` strips directory segments |
| File type | Trusts client MIME | Server maps extension → Content-Type; further hardening in section 7 |
| 404 handling | Next.js serves blank/error | Explicit `{ success: false, "Image not found" }` JSON |
| URL stability | Tied to public path | Stable `/api/<type>/images/<name>` shape |
| Backend swap | Rewrite everything | Swap `readFile` → object-storage GET without touching stored URLs |

**Cache-Control is the big performance win.** Because each uplance name is unique, the browser can cache forever with `immutable` — uploaded images are fetched exactly once per browser and never revalidated on repeat visits.

The **stable URL shape** also enables two important workflows:

- **URL normalization** — if older records stored legacy `/images/blog/x.jpg` paths, a small util can rewrite them to the canonical `/api/blog/images/x.jpg` before render, so old + new data display identically.
- **Orphan cleanup** — because every stored URL maps to exactly one file, CRUD routes can compare "which URLs are still referenced" against "which files exist on disk" and `unlink` the dead ones on update/delete. This prevents `public/images/` from growing forever.
- **`next/image` compatibility** — the serving route returns an exact `Content-Type` and a long `immutable` cache, which is exactly what the image optimizer expects from an upstream. Uploaded images can therefore be rendered with `<Image>` (section 6.1), with `src` pointing straight at the API URL.

---

## 6. Displaying Uploaded Images

### 6.1 DB-driven (API-served) images → `next/image`

Use `<Image>` for uploaded images too — you get lazy loading, responsive `srcset`, WebP/AVIF, and layout-shift prevention. The optimizer fetches the same-origin `/api/...` URL server-side, so no remote config is needed.

Known / intrinsic dimensions — pass explicit `width`/`height`:

```tsx
import Image from "next/image";

<Image
  src={imageUrl ?? "/placeholder.jpg"}
  alt="uploaded image"
  width={1600}
  height={900}
  className="w-full h-auto rounded-2xl"
/>
```

Unknown / responsive dimensions — use `fill` and size the parent:

```tsx
<div className="relative aspect-video w-full overflow-hidden rounded-2xl">
  <Image
    src={imageUrl ?? "/placeholder.jpg"}
    alt="uploaded image"
    fill
    sizes="(max-width: 768px) 100vw, 50vw"
    className="object-cover"
  />
</div>
```

Critical caveats:

- **The optimizer does not forward request headers.** The default loader fetches `src` server-side without cookies/auth. If your serving route is authenticated, optimization will fail — pass `unoptimized` so `<Image>` serves the raw URL directly (it still inherits lazy loading and CLS prevention):
  ```tsx
  <Image src={url} alt="uploaded image" width={800} height={600} unoptimized />
  ```
  Public, unauthenticated serving routes can keep the optimizer enabled.
- **`localPatterns` whitelist** — restrict which local paths the optimizer is allowed to fetch, so your `/api/...` image routes are the only ones it proxies:
  ```ts
  // next.config.ts
  images: {
    localPatterns: [{ pathname: "/api/*/images/**", search: "" }],
  }
  ```
- **SVG and animated GIF are never optimized** — Next serves them as-is. Recommend explicit `unoptimized` for SVGs; proxying them is the XSS risk described in 3.8.

Conventions:

- Always provide a fallback (`/placeholder.jpg`) for missing/null URLs.
- Store the API URL string (`/api/blog/images/x.jpg`) in your data layer; pass it straight to `src`.
- No `eslint-disable` comment needed — `<Image>` is the blessed component.

### 6.2 Static, remote & object-storage images → `next/image`

Committed assets under `public/`, whitelisted remote hosts, and CDN-backed object storage all keep using `<Image/>`. Remote URLs need a whitelist:

```ts
// next.config.ts
images: {
  localPatterns: [
    { pathname: "/api/*/images/**", search: "" }, // your upload serving routes
  ],
  remotePatterns: [
    { protocol: "https", hostname: "cdn.example.com" }, // object-storage CDN
  ],
}
```

No config is needed for assets committed in `public/`.

---

## 7. Production Hardening Checklist

The API pattern fixes the structural flaws, but for a production deploy add these:

- **Server-side size limit** — before calling `arrayBuffer()`, check `file.size` against a constant (e.g., `MAX_FILE_SIZE = 5 * 1024 * 1024`) and return `413` when exceeded. Do not rely on the client enforcing limits.
- **Magic-byte sniffing, not MIME trust** — check the file's actual first bytes against real signatures (`FF D8 FF` for JPEG, `89 50 4E 47` for PNG, `RIFF....WEBP` for WebP). A spoofed MIME type is trivial to send.
- **Authenticate the upload route** — the same `requireAuth`/token check used elsewhere in your API should gate `POST /api/upload`. In a dashboard-driven content flow, only signed-in editors should be able to write.
- **Serve SVG with care or disallow it** — SVGs can carry scripts. Either strip `<script>`/`foreignObject`, serve them with `Content-Disposition: attachment`, or exclude `.svg` from the accepted extensions.
- **Serve from object storage on serverless** — if you deploy to Vercel/Netlify/Cloudflare, `public/` is the wrong place for runtime uploads (see 3.5). Use a real object store instead:
  - **Vercel Blob** — designed for exactly this on Vercel.
  - **S3-compatible storage** (AWS S3, Cloudflare R2, Supabase Storage) — swap the `writeFile` call in the upload route for an SDK `put`, and the `readFile` call in the serving route for a `get` (or just store the public CDN URL).
  - The URL shape returned by the upload route stays effectively the same from the client's point of view, so migrating later is a small change.
  - Serve the resulting CDN URL through `<Image>` — add the host to `images.remotePatterns` and the optimizer keeps working (6.2).
- **Add a rate limit** on the upload route to clamp down on disk/bandwidth abuse.

---

## 8. Flow Diagram

```
User picks a file in a composer modal (client component)
        │
        ▼
uploadImage(file, "blog")                       src/lib/upload.ts
        │  FormData: file + folder
        ▼
POST /api/upload                                 src/app/api/upload/route.ts
        │  MIME check → collision-safe name → mkdir + writeFile
        ▼
{ success: true, data: { url: "/api/blog/images/1710-<uuid>.jpg" } }
        │
        ▼
URL saved to DB (e.g., Post.thumbnailImage)
        │
        ▼
Page renders                                        public blog list / detail
        │
        ▼
<Image fill src="/api/blog/images/1710-<uuid>.jpg" />    (normalize URL first)
        │
        ▼
GET /api/blog/images/[filename]                    src/app/api/blog/images/[filename]/route.ts
        │  path.basename() guard → readFile → Content-Type → immutable cache
        ▼
200 + image bytes (cached for 1 year) / 404 "Image not found"
```

---

## 9. File Reference Map

| File | Responsibility |
|------|----------------|
| `src/app/api/upload/route.ts` | Validate, rename, and persist uploads to `public/images/<folder>/`; return the API URL |
| `src/app/api/<type>/images/[filename]/route.ts` | Read the file from disk and serve it with Content-Type + immutable cache; `404` fallback |
| `src/lib/upload.ts` | Client helper: `uploadImage(file, folder)` → returns URL ready for the DB |
| `src/utils/*-image.ts` | Normalize legacy `/images/...` URLs to the canonical `/api/...` form |
| `src/utils/*-file-cleanup.ts` | Delete orphaned files on entity update/delete |
| `next.config.ts` | `images.localPatterns` for upload serving routes + `images.remotePatterns` for CDN hosts |
| `.env` / database | Store the returned `/api/...` URL strings for each entity |