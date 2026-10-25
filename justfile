# Run recipes with the tool versions configured in mise.toml, including from IDEs.
set shell := ["mise", "exec", "--", "sh", "-eu", "-c"]

# Show available recipes.
default:
    @just --list

# Install dependencies, run checks, and rebuild the committed dist/ bundle (Node.js 24).
dist:
    node scripts/require-node24.cjs
    npm ci
    npm run typecheck
    npm test
    npm run build
