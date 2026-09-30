```sh
# Enter the site directory from the repository root.
cd site
# Install the exact dependency versions in the lockfile.
npm ci
```

```sh
# Start the local development server with live updates.
npm run dev
```

```sh
# Format the site source files.
npm run format
# Check formatting without changing files.
npm run format:check
```

```sh
# Check types and build the local preview with indexing disabled.
npm run build
# Run browser tests against the compiled local preview.
npm test
# Serve the compiled site on localhost.
npm run preview
```

```sh
# Build locally for GitHub Pages with public SEO metadata; does not publish.
SITE_URL=https://lmh-java.github.io SITE_BASE=/CloudGym npm run build
# Test the production build using the GitHub Pages base path.
SITE_URL=https://lmh-java.github.io SITE_BASE=/CloudGym npm test
# Preview the production build locally under /CloudGym/.
SITE_URL=https://lmh-java.github.io SITE_BASE=/CloudGym npm run preview
```

```sh
# Run GitHub Actions checks on main without publishing.
gh workflow run site.yml --ref main -f publish=false
```

```sh
# Build, test, and publish main to GitHub Pages after design approval.
gh workflow run site.yml --ref main -f publish=true
```
