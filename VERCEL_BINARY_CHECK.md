# Vercel Binary Deployment Check

## ✅ Binary Status in Git

```bash
✅ Binary committed: web/bin/vanguard (commit 1adff52)
✅ Binary size: ~1.4MB
✅ File tracked in repository
✅ No .vercelignore file blocking it
```

---

## 🔍 Why Vercel Might Not See It

### Issue 1: Root Directory Setting
**Most Likely Cause!**

If Vercel Root Directory is set to `web`, then:
- Vercel sees: `./` (root of web directory)
- Binary should be at: `./bin/vanguard` ✅
- But git has it at: `web/bin/vanguard` ✅

**This should work!** But let's verify...

### Issue 2: Deployment Source
Check which commit Vercel is deploying:

1. Go to: https://vercel.com/blueskylabs/stealth/deployments
2. Click latest deployment
3. Check **"Source"** - should show commit `1adff52` or later
4. If it's older, Vercel hasn't deployed the binary commit yet

---

## 🔧 Verify Binary in Deployment

### Method 1: Check Deployment Files (Vercel Dashboard)

1. Go to: https://vercel.com/blueskylabs/stealth/deployments
2. Click latest deployment
3. Click **"Source"** tab
4. Look for `bin/vanguard` in file list
5. If missing → binary not included

### Method 2: Check via API Route

Add this temporary endpoint to check:

**File:** `web/app/api/check-binary/route.ts`

```typescript
import { NextResponse } from 'next/server';
import { existsSync, statSync } from 'fs';
import path from 'path';

export async function GET() {
  const binaryPath = path.join(process.cwd(), 'bin', 'vanguard');
  
  const exists = existsSync(binaryPath);
  
  if (exists) {
    const stats = statSync(binaryPath);
    return NextResponse.json({
      exists: true,
      path: binaryPath,
      size: stats.size,
      mode: stats.mode.toString(8),
      isFile: stats.isFile(),
      cwd: process.cwd()
    });
  }
  
  return NextResponse.json({
    exists: false,
    path: binaryPath,
    cwd: process.cwd(),
    cwdContents: require('fs').readdirSync(process.cwd())
  });
}
```

Then visit: `https://your-site.vercel.app/api/check-binary`

---

## 🎯 Most Likely Solutions

### Solution 1: Trigger Fresh Deployment

The binary commit might not have triggered Vercel yet:

```bash
# Force Vercel to redeploy
git commit --allow-empty -m "trigger: redeploy with binary"
git push origin master
```

### Solution 2: Check Vercel Root Directory

1. Go to: https://vercel.com/blueskylabs/stealth/settings
2. **General** → **Root Directory**
3. Should be: `web`
4. If different, update and redeploy

### Solution 3: Manual Verification

Check if binary is in the actual deployment:

1. Go to deployment logs
2. Look for file listing
3. Search for `bin/vanguard`

---

## 📊 Expected File Structure

### In Git Repository:
```
stealth/
├── core/
└── web/
    ├── app/
    ├── bin/
    │   └── vanguard  ← Binary here
    └── package.json
```

### In Vercel (Root Directory = web):
```
/var/task/              ← Vercel's working directory
├── app/
├── bin/
│   └── vanguard       ← Binary should be here
└── package.json
```

### Binary Path in Code:
```typescript
path.join(process.cwd(), 'bin', 'vanguard')
→ /var/task/bin/vanguard
```

---

## 🚀 Quick Action Plan

1. **Check latest deployment commit:**
   - Should be `1adff52` or later
   - If older → wait for new deployment

2. **Create check endpoint:**
   - Add `/api/check-binary` route above
   - Deploy and visit it
   - See if binary exists

3. **Force redeploy if needed:**
   ```bash
   git commit --allow-empty -m "redeploy: include binary"
   git push origin master
   ```

4. **Check Vercel logs:**
   - Look for binary in deployment files
   - Check build logs for any errors

---

## 🔍 Debug Output

When you check `/api/check-binary`, you should see:

```json
{
  "exists": true,
  "path": "/var/task/bin/vanguard",
  "size": 1468416,
  "mode": "100755",
  "isFile": true,
  "cwd": "/var/task"
}
```

If `exists: false`, the binary is not in the deployment.

---

**Try creating the check endpoint first to see if the binary is actually there!**

