# NotesAI — PWA Guide

## Overview

NotesAI is a Progressive Web App (PWA) that can be installed on Android phones and desktops. It provides an app-like experience with offline support.

## Installation

### Android (Chrome)
1. Open NotesAI in Chrome
2. Tap "Add to Home Screen" (Chrome will show install prompt)
3. App icon appears on home screen
4. Tap to open in standalone mode (no browser UI)

### Desktop (Chrome/Edge)
1. Open NotesAI in browser
2. Click the install icon in the address bar
3. App opens in standalone window

### iOS (Safari)
1. Open NotesAI in Safari
2. Tap Share → "Add to Home Screen"
3. App icon appears on home screen

## PWA Features

### Web App Manifest (`/manifest.json`)
- Name: "NotesAI — Premium Workspace"
- Short name: "NotesAI"
- Display: standalone
- Theme color: #1e3a8a (Royal Blue)
- Background color: #0f172a (Navy)
- 8 icon sizes: 72x72 to 512x512
- 3 shortcuts: Create PDF, Study, Documents

### Service Worker (`/sw.js`)
- **App shell caching:** Precaches icons and offline page
- **Network-first for pages:** Tries network, falls back to cache, then offline page
- **Cache-first for static assets:** Icons, CSS, JS cached for fast load
- **No API caching:** Authenticated API responses are NEVER cached
- **No private data caching:** JWT tokens and user data are NOT cached
- **Update detection:** Checks for new version, prompts user to reload

### Offline Fallback (`/offline`)
- Branded offline page with connection retry
- Auto-reloads when connection is restored
- Shows "You're Offline" message with retry button

### Network Status
- Online/offline event listeners
- Toast notification when connection changes
- Offline indicator on page

## Offline Behavior

| Feature | Online | Offline |
|---------|--------|---------|
| View cached pages | ✅ | ✅ (from cache) |
| View documents | ✅ | ❌ (requires server) |
| Generate PDF | ✅ | ❌ (requires server) |
| AI Study | ✅ | ❌ (requires server) |
| Login/Register | ✅ | ❌ (requires server) |
| Static assets (icons, CSS) | ✅ | ✅ (cached) |
| Offline page | N/A | ✅ (shown when no connection) |

## Security

### What is NOT cached (by design):
- JWT tokens (access/refresh)
- User profile data
- Document content/metadata
- PDF files
- AI extraction results
- API responses (authenticated)
- Admin data

### What IS cached:
- App shell (HTML, CSS, JS)
- Static icons
- Offline fallback page
- Navigation page shells (for offline viewing)

## Updates

When a new version is deployed:
1. Service worker detects update on next visit
2. User is prompted: "A new version is available. Reload to update?"
3. On confirmation, new service worker activates
4. Old cache is cleared, new assets cached

## Testing PWA Installation

### Chrome DevTools (Desktop)
1. Open Chrome DevTools → Application tab
2. Check "Manifest" section for validity
3. Check "Service Workers" section for registration
4. Use "Lighthouse" → "PWA" audit

### Android
1. Open in Chrome on Android
2. Check for "Add to Home Screen" prompt
3. Install and verify standalone mode
4. Test offline functionality

### Verification Checklist
- [ ] Manifest loads without errors
- [ ] Service worker registers successfully
- [ ] All 8 icons load correctly
- [ ] Offline page displays when no connection
- [ ] App installs to home screen
- [ ] Standalone mode works (no browser UI)
- [ ] Update notification appears on new version
- [ ] No private data in cache (DevTools → Application → Cache Storage)
