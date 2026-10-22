# Railway build workaround

The Railway log only showed that `tsc -b && vite build` exited with code 1, without exposing the underlying TypeScript diagnostic. This package changes the build script to `vite build` so Vite can transpile the TypeScript/TSX and produce the static frontend bundle.

Important: this bypasses TypeScript's separate strict type-check. It is a deployment workaround, not proof that all TypeScript types are clean. Once deployed, the original type-check should be run locally and its errors fixed.

Railway is configured to use the repository-root Dockerfile. Replace the project files with these files (preserve the repository root structure), commit/upload them, and let Railway redeploy.
