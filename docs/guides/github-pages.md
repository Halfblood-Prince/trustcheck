# GitHub Pages setup

This repository is a good fit for GitHub Pages because the docs are static and documentation-focused.

## What is included in this repo setup

- `mkdocs.yml` for site configuration
- `docs/` for content
- `.github/workflows/docs.yml` for build and deploy

## Enable Pages in GitHub

In the repository settings, set **Pages** to deploy from **GitHub Actions**.

## Local preview

```bash
python -m pip install mkdocs-material
mkdocs serve
```

## Production build

```bash
python -m pip install mkdocs-material
mkdocs build
```

## Custom domain

If you later add a custom domain, you can extend the Pages setup with a `CNAME` file and update `site_url` in `mkdocs.yml`.
