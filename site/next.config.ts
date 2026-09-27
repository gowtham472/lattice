import path from "node:path";
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // a static site: `npm run build` writes plain HTML, CSS and JS to out/, hostable anywhere
  output: "export",
  images: { unoptimized: true },
  // the repository also holds the cockpit's lockfile; this app's root is this folder
  turbopack: { root: path.join(__dirname) },
};

export default nextConfig;
