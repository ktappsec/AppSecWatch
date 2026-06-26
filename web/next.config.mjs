/** @type {import('next').NextConfig} */
// NEXT_OUTPUT=export → static HTML export (out/), served by FastAPI in the
// single Docker image. Unset → normal dev/build (Node server) for local work.
const isExport = process.env.NEXT_OUTPUT === "export";

const nextConfig = {
  reactStrictMode: true,
  ...(isExport
    ? {
        output: "export",
        trailingSlash: true, // every route → dir/index.html (clean static serving)
        images: { unoptimized: true },
      }
    : {}),
};

export default nextConfig;
