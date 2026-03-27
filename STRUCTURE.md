# CyberForge Atlas: Technical Structure

This document outlines the project architecture and identifies key files for modification.

## 📂 Directory Overview

### `/src` - Frontend Source
The heart of the Atlas interface.
- **`App.jsx`**: **The Logic Hub.** Controls search behavior, category selection, and incremental rendering. Modify this to change UI behavior or add new features.
- **`App.css`**: **The Aesthetic Engine.** Contains all cyberpunk styles, glassmorphic effects, and neon colors. Change this to overhaul the "look and feel."
- **`main.jsx`**: Standard entry point.

### `/public` - Static Data & Assets
Where the intelligence is stored and served.
- **`data/attack-database.json`**: **The Intelligence Vault.** Contains all ingested attack data, payloads, and guides.
- **`data/attack-index.json`**: **The Search Matrix.** Pre-computed Fuse.js index for instant searching.
- **`logo.svg`**: Your custom CyberForge logo.
- **`icons.svg`**: SVG sprite sheet for category icons.

### `/scripts` - Processing Engine
Tools for maintaining the knowledge base.
- **`build-knowledge.mjs`**: **The Ingestion Engine.** Scans source folders and generates the JSON database. Modify the `taxonomy` object here to add new categories.

### `/` - Configuration
- **`package.json`**: Dependency and script management.
- **`index.html`**: The document skeleton (contains the favicon link).

---

## 🛠️ "I want to change..." Cheat Sheet

| I want to change... | Target File |
| :--- | :--- |
| **New Attack Category** | Edit `scripts/build-knowledge.mjs` -> `sectionMatchers` / `taxonomy`. |
| **UI Color / Neon Glow** | Edit `src/App.css` (specifically CSS variables like `--neon-green`). |
| **Search Speed/Fuzziness** | Edit `src/App.jsx` -> `fuseOptions`. |
| **Logo or Favicon** | Replace `public/logo.svg`. |
| **Add a new field to UI** | Edit `src/App.jsx` in the `renderSectionContent` function. |
| **Update the Data** | Add sources to `scripts/build-knowledge.mjs` and run `npm run build:knowledge`. |

---
*Created for CyberForge Operations.*
