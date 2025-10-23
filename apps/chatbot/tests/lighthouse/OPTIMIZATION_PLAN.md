# Lighthouse Performance Optimization Plan
**Date**: October 21, 2025
**Test URL**: https://cwe.crashedmind.com/
**Lighthouse Version**: 12.6.0

## Executive Summary

### Current Scores
- **Performance**: 48/100 ⚠️ CRITICAL
- **Accessibility**: 93/100 ⚠️ Minor issues
- **Best Practices**: 96/100 ✅ Good
- **SEO**: 83/100 ⚠️ Needs improvement

### Critical Performance Metrics
| Metric | Current | Target | Status |
|--------|---------|--------|--------|
| **First Contentful Paint (FCP)** | 7.6s | <1.8s | 🔴 CRITICAL (4.2x slower) |
| **Largest Contentful Paint (LCP)** | 8.1s | <2.5s | 🔴 CRITICAL (3.2x slower) |
| **Speed Index** | 7.6s | <3.0s | 🔴 CRITICAL (2.5x slower) |
| **Total Blocking Time (TBT)** | 420ms | <200ms | 🟡 POOR (2.1x slower) |
| **Cumulative Layout Shift (CLS)** | 0 | <0.1 | ✅ EXCELLENT |

### Key Findings
1. **Massive JavaScript bundle**: 1,043 KB (336 KB unused = 33% waste)
2. **Render-blocking resources**: 1,450ms blocking time
3. **No caching strategy**: 1,090 KB could be cached
4. **Main thread bottleneck**: 3.0s of work blocking interactivity

---

## Priority 1: CRITICAL Performance Issues (P0)
*Impact: 5-7 second improvement in load time*

### 1.1 Reduce JavaScript Bundle Size 🔴 HIGH IMPACT
**Current Problem**: 1,043 KB JavaScript bundle with 336 KB (33%) unused code

**Root Causes**:
- No code splitting - entire app loaded upfront
- Unused dependencies included in bundle
- No tree-shaking optimization
- Chainlit framework includes unnecessary features

**Solutions** (in order):
1. **Implement code splitting** (Est. savings: 300-500 KB)
   ```javascript
   // Split routes with dynamic imports
   const AdminPanel = lazy(() => import('./AdminPanel'));
   const ChatHistory = lazy(() => import('./ChatHistory'));
   ```
   - Split admin features from main chat interface
   - Load chat history only when requested
   - Lazy load markdown/code rendering libraries

2. **Analyze bundle with webpack-bundle-analyzer** (Est. savings: 100-200 KB)
   ```bash
   npm install --save-dev webpack-bundle-analyzer
   # Identify largest dependencies
   ```
   - Remove unused dependencies (date-fns, moment.js duplicates)
   - Replace heavy libraries with lighter alternatives
   - Check for duplicate dependencies in bundle

3. **Enable tree-shaking** (Est. savings: 50-100 KB)
   ```javascript
   // Use named imports instead of default
   import { specific, functions } from 'library';
   ```
   - Configure Vite/Webpack for tree-shaking
   - Use ES6 modules throughout
   - Remove unused exports

**Expected Impact**: FCP -2.5s, LCP -2.0s
**Effort**: 2-3 days
**Priority**: P0 - Start immediately

---

### 1.2 Eliminate Render-Blocking Resources 🔴 HIGH IMPACT
**Current Problem**: 1,450ms of render-blocking CSS and fonts

**Blocking Resources**:
1. `index-CrZ89Sf1.css` - 13.9 KB, 450ms blocking
2. `katex.min.css` - 3.8 KB, 762ms blocking (CDN)
3. Google Fonts - 1.2 KB, 765ms blocking

**Solutions** (in order):
1. **Inline critical CSS** (Est. savings: 450ms)
   ```html
   <style>
     /* Critical above-the-fold CSS inline in <head> */
     .chat-container { ... }
     .message-input { ... }
   </style>
   <link rel="preload" href="/assets/index.css" as="style" onload="this.onload=null;this.rel='stylesheet'">
   ```
   - Extract and inline critical CSS (<14 KB)
   - Defer non-critical CSS loading
   - Use `rel="preload"` for async CSS loading

2. **Self-host and optimize KaTeX CSS** (Est. savings: 762ms)
   ```html
   <!-- Instead of CDN -->
   <link rel="stylesheet" href="/assets/katex.min.css">
   ```
   - Download KaTeX CSS to local assets
   - Inline only if used above-fold
   - Consider lazy-loading if math rendering is rare

3. **Optimize font loading** (Est. savings: 765ms)
   ```html
   <link rel="preconnect" href="https://fonts.googleapis.com">
   <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
   <link rel="preload" href="/fonts/Inter-var.woff2" as="font" type="font/woff2" crossorigin>
   ```
   - Self-host Inter font (single variable font file)
   - Use `font-display: swap` to prevent FOIT
   - Preload only used font weights (400, 500, 700)

**Expected Impact**: FCP -1.5s, LCP -1.0s
**Effort**: 1-2 days
**Priority**: P0 - Start immediately

---

### 1.3 Implement Aggressive Caching Strategy 🔴 MEDIUM IMPACT
**Current Problem**: 1,090 KB of resources with poor cache headers

**Uncached Resources**:
- JavaScript bundle: 1,043 KB (no caching)
- CSS files: 13.9 KB (no caching)
- Fonts: 47.3 KB (no caching)

**Solutions**:
1. **Configure Cache-Control headers** (Est. savings: 1,090 KB on repeat visits)
   ```nginx
   # In Cloud Run nginx config or Cloud CDN
   location ~* \.(js|css|woff2)$ {
       expires 1y;
       add_header Cache-Control "public, immutable";
   }

   location ~* \.(png|jpg|svg)$ {
       expires 1y;
       add_header Cache-Control "public, immutable";
   }

   location / {
       expires -1;
       add_header Cache-Control "no-cache, must-revalidate";
   }
   ```

2. **Implement content-hash filenames** (Already done: `index-C30sRNGJ.js`)
   - Verify Vite is generating hashed filenames ✅
   - Ensure all assets use hash-based names

3. **Enable HTTP/2 Server Push** (Optional)
   ```nginx
   http2_push /assets/index-C30sRNGJ.js;
   http2_push /assets/index-CrZ89Sf1.css;
   ```

**Expected Impact**: Second load: FCP -5s, LCP -5s
**Effort**: 0.5 days (configuration only)
**Priority**: P0 - Quick win

---

### 1.4 Reduce Main Thread Work 🔴 HIGH IMPACT
**Current Problem**: 3.0s of main thread work, 2.1s JavaScript execution time

**Root Causes**:
- Large JavaScript parsing/compilation (1,043 KB)
- Synchronous operations blocking rendering
- Unnecessary re-renders in React/Chainlit

**Solutions**:
1. **Defer non-critical JavaScript** (Est. savings: 1.0s)
   ```html
   <script src="/analytics.js" defer></script>
   <script src="/chat-history.js" defer></script>
   ```
   - Move analytics to end of body
   - Defer chat history loading
   - Use `requestIdleCallback` for low-priority tasks

2. **Optimize JavaScript execution** (Est. savings: 0.5s)
   ```javascript
   // Use Web Workers for heavy computation
   const worker = new Worker('/embedding-worker.js');
   worker.postMessage({ text: userMessage });
   ```
   - Move embedding calculations to Web Workers
   - Use `requestAnimationFrame` for UI updates
   - Debounce expensive operations (search, filtering)

3. **Code splitting (already covered in 1.1)** (Est. savings: 0.5s)

**Expected Impact**: TBT -200ms, TTI -2.0s
**Effort**: 2-3 days
**Priority**: P0 - After 1.1 (depends on code splitting)

---

## Priority 2: Important Optimizations (P1)
*Impact: 1-2 second improvement*

### 2.1 Optimize Image Delivery 🟡 MEDIUM IMPACT
**Current Problem**: 35 KB savings available from next-gen formats

**Issues**:
- Logo: 39.5 KB (likely PNG/SVG)
- No WebP/AVIF format support
- No responsive images

**Solutions**:
1. **Convert images to next-gen formats** (Est. savings: 35 KB)
   ```html
   <picture>
     <source srcset="/logo.avif" type="image/avif">
     <source srcset="/logo.webp" type="image/webp">
     <img src="/logo.png" alt="CWE ChatBot">
   </picture>
   ```
   - Convert logo to WebP/AVIF
   - Serve based on browser support
   - Compress with optimized quality (80-85%)

2. **Implement lazy loading** (Est. savings: 200-500ms)
   ```html
   <img src="/logo.png" loading="lazy" alt="CWE ChatBot">
   ```
   - Add `loading="lazy"` to below-fold images
   - Use Intersection Observer for custom lazy loading

**Expected Impact**: LCP -200ms
**Effort**: 0.5 days
**Priority**: P1 - Quick win after P0 items

---

### 2.2 Fix Accessibility Issues 🟡 MEDIUM PRIORITY
**Current Problem**: 7% accessibility score deduction

**Issues**:
1. **5 buttons without accessible names** (WCAG violation)
   ```html
   <!-- BAD -->
   <button><icon /></button>

   <!-- GOOD -->
   <button aria-label="Send message"><icon /></button>
   ```

2. **1 ARIA role incompatibility**
   - Review ARIA roles on elements
   - Ensure semantic HTML is used correctly

**Solutions**:
1. **Add aria-label to icon-only buttons**
   ```javascript
   // Chainlit customization
   <IconButton aria-label="Clear conversation">
     <ClearIcon />
   </IconButton>
   ```

2. **Fix ARIA role misuse**
   - Run axe DevTools to identify specific element
   - Use semantic HTML instead of ARIA when possible

**Expected Impact**: Accessibility +7%
**Effort**: 0.5 days
**Priority**: P1 - Legal/compliance requirement

---

### 2.3 Improve SEO Metadata 🟡 LOW-MEDIUM PRIORITY
**Current Problem**: 17% SEO score deduction

**Issues**:
1. **Missing meta description** (impacts search rankings)
2. **Invalid robots.txt** (impacts crawlability)

**Solutions**:
1. **Add meta description** (Est. impact: +10% SEO)
   ```html
   <meta name="description" content="CWE ChatBot - Conversational AI for MITRE Common Weakness Enumeration. Ask questions about security vulnerabilities, get CWE mappings, and create PSIRT advisories.">
   ```

2. **Fix robots.txt** (Est. impact: +7% SEO)
   ```txt
   User-agent: *
   Allow: /

   Sitemap: https://cwe.crashedmind.com/sitemap.xml
   ```

**Expected Impact**: SEO +17%
**Effort**: 0.25 days
**Priority**: P1 - Low effort, high ROI

---

## Priority 3: Advanced Optimizations (P2)
*Impact: <1 second improvement*

### 3.1 Enable Back/Forward Cache 🟡 LOW-MEDIUM IMPACT
**Current Problem**: Page prevented bfcache restoration (1 failure reason)

**Solutions**:
1. **Identify bfcache blockers**
   ```javascript
   // Check for common blockers
   // - unload event listeners
   // - IndexedDB transactions
   // - Fetch requests in progress
   ```

2. **Remove bfcache blockers**
   ```javascript
   // Use pagehide instead of unload
   window.addEventListener('pagehide', () => {
     // Cleanup
   });
   ```

**Expected Impact**: Instant back/forward navigation
**Effort**: 1 day
**Priority**: P2 - Nice to have

---

### 3.2 Reduce Unused CSS 🟡 LOW IMPACT
**Current Problem**: 12 KB unused CSS

**Solutions**:
1. **Use PurgeCSS or similar** (Est. savings: 12 KB)
   ```javascript
   // In Vite config
   import purgecss from '@fullhuman/postcss-purgecss';

   export default {
     css: {
       postcss: {
         plugins: [
           purgecss({
             content: ['./src/**/*.tsx', './src/**/*.html']
           })
         ]
       }
     }
   };
   ```

**Expected Impact**: LCP -50ms
**Effort**: 0.5 days
**Priority**: P2 - Low impact

---

## Implementation Roadmap

### Sprint 1: Critical Performance (Week 1-2)
**Goal**: Achieve Performance score >70, FCP <3s, LCP <4s

1. **Day 1-2**: Implement aggressive caching (P0-1.3)
   - Configure Cache-Control headers
   - Test cache effectiveness
   - **Expected**: Second load performance: 90+

2. **Day 3-4**: Eliminate render-blocking CSS (P0-1.2)
   - Inline critical CSS
   - Self-host KaTeX and fonts
   - **Expected**: FCP 6.1s → 4.6s

3. **Day 5-7**: Analyze and reduce JavaScript bundle (P0-1.1 part 1)
   - Run webpack-bundle-analyzer
   - Remove unused dependencies
   - **Expected**: FCP 4.6s → 3.8s

4. **Day 8-10**: Implement code splitting (P0-1.1 part 2)
   - Split routes and features
   - Lazy load heavy components
   - **Expected**: FCP 3.8s → 2.5s, LCP 8.1s → 3.5s

**Sprint 1 Target**: Performance 70-75, FCP 2.5s, LCP 3.5s

---

### Sprint 2: Optimization & Polish (Week 3)
**Goal**: Achieve Performance score >85, FCP <2s, LCP <2.5s

1. **Day 11-13**: Reduce main thread work (P0-1.4)
   - Defer non-critical JavaScript
   - Move heavy work to Web Workers
   - **Expected**: TBT 420ms → 220ms, FCP 2.5s → 1.8s

2. **Day 14-15**: Image optimization (P1-2.1)
   - Convert to WebP/AVIF
   - Implement lazy loading
   - **Expected**: LCP 3.5s → 2.8s

3. **Day 15**: Accessibility fixes (P1-2.2)
   - Add aria-labels
   - Fix ARIA roles
   - **Expected**: Accessibility 93% → 100%

4. **Day 15**: SEO improvements (P1-2.3)
   - Add meta description
   - Fix robots.txt
   - **Expected**: SEO 83% → 100%

**Sprint 2 Target**: Performance 85-90, FCP <2s, LCP <2.5s, A11y 100%, SEO 100%

---

### Sprint 3: Advanced Optimizations (Week 4 - Optional)
**Goal**: Achieve Performance score >90

1. **Enable bfcache** (P2-3.1)
2. **Reduce unused CSS** (P2-3.2)
3. **Performance monitoring setup**
   - Real User Monitoring (RUM)
   - Lighthouse CI integration
   - Performance budgets

**Sprint 3 Target**: Performance >90, Best Practices 100%

---

## Success Metrics & Targets

### Performance Targets (End of Sprint 2)
| Metric | Current | Sprint 1 | Sprint 2 | Target |
|--------|---------|----------|----------|--------|
| **Performance Score** | 48 | 70-75 | 85-90 | >85 |
| **FCP** | 7.6s | 2.5s | 1.8s | <1.8s ✅ |
| **LCP** | 8.1s | 3.5s | 2.5s | <2.5s ✅ |
| **Speed Index** | 7.6s | 3.0s | 2.0s | <3.0s ✅ |
| **TBT** | 420ms | 350ms | 200ms | <200ms ✅ |
| **CLS** | 0 | 0 | 0 | <0.1 ✅ |

### Overall Quality Targets
| Category | Current | Target | Status |
|----------|---------|--------|--------|
| **Performance** | 48 | >85 | 🔴 Sprint 1-2 required |
| **Accessibility** | 93 | 100 | 🟡 Sprint 2 |
| **Best Practices** | 96 | >95 | ✅ Maintained |
| **SEO** | 83 | 100 | 🟡 Sprint 2 |

---

## Risk Assessment & Mitigation

### Technical Risks

1. **Code Splitting Complexity** (P0-1.1)
   - **Risk**: Chainlit framework may not support easy code splitting
   - **Mitigation**: Test with simple route split first, fallback to manual chunking
   - **Fallback**: Use dynamic imports for heavy libraries only

2. **Cache-Control Conflicts** (P0-1.3)
   - **Risk**: Cloud Run default headers may override custom headers
   - **Mitigation**: Test with Cloud CDN configuration, use Cloud Armor rules
   - **Fallback**: Implement Service Worker caching strategy

3. **Font Loading Performance** (P0-1.2)
   - **Risk**: Self-hosted fonts may increase initial page weight
   - **Mitigation**: Use variable fonts (single file), preload critical fonts
   - **Fallback**: Keep system fonts as fallback with `font-display: swap`

### Business Risks

1. **User Experience During Optimization**
   - **Risk**: Changes may temporarily break functionality
   - **Mitigation**: Use feature flags, deploy to staging first
   - **Rollback Plan**: Keep previous deployment available, use Cloud Run traffic splitting

2. **Development Resource Allocation**
   - **Risk**: 3-4 weeks of focused optimization work
   - **Mitigation**: Prioritize P0 items for immediate impact, P1/P2 can be deferred
   - **Alternative**: Outsource specific tasks (image optimization, bundle analysis)

---

## Monitoring & Continuous Optimization

### 1. Set Up Lighthouse CI
```yaml
# .github/workflows/lighthouse.yml
name: Lighthouse CI
on: [pull_request]
jobs:
  lighthouse:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run Lighthouse CI
        uses: treosh/lighthouse-ci-action@v9
        with:
          urls: |
            https://staging.cwe.crashedmind.com/
          budgetPath: ./lighthouse-budget.json
          uploadArtifacts: true
```

### 2. Performance Budgets
```json
// lighthouse-budget.json
{
  "resourceSizes": [
    { "resourceType": "script", "budget": 700 },
    { "resourceType": "stylesheet", "budget": 30 },
    { "resourceType": "image", "budget": 100 }
  ],
  "resourceCounts": [
    { "resourceType": "third-party", "budget": 5 }
  ],
  "timings": [
    { "metric": "first-contentful-paint", "budget": 2000 },
    { "metric": "largest-contentful-paint", "budget": 2500 },
    { "metric": "total-blocking-time", "budget": 200 }
  ]
}
```

### 3. Real User Monitoring (RUM)
```javascript
// Add to main.tsx
import { initRUM } from '@google-cloud/rum';

initRUM({
  projectId: 'cwechatbot',
  // Track Core Web Vitals
  trackCoreWebVitals: true,
  // Custom metrics
  customMetrics: ['chat-response-time', 'embedding-generation-time']
});
```

---

## Cost-Benefit Analysis

### Estimated ROI by Priority

| Priority | Effort (days) | Performance Gain | User Impact | ROI |
|----------|---------------|------------------|-------------|-----|
| **P0-1.1** Code Splitting | 2-3 | FCP -2.5s, LCP -2.0s | 🔥 CRITICAL | ⭐⭐⭐⭐⭐ |
| **P0-1.2** Render-Blocking | 1-2 | FCP -1.5s, LCP -1.0s | 🔥 CRITICAL | ⭐⭐⭐⭐⭐ |
| **P0-1.3** Caching | 0.5 | Second load -5s | 🔥 CRITICAL | ⭐⭐⭐⭐⭐ |
| **P0-1.4** Main Thread | 2-3 | TTI -2.0s, TBT -200ms | 🔥 HIGH | ⭐⭐⭐⭐ |
| **P1-2.1** Images | 0.5 | LCP -200ms | 🟡 MEDIUM | ⭐⭐⭐ |
| **P1-2.2** Accessibility | 0.5 | A11y +7% | 🟡 LEGAL | ⭐⭐⭐⭐ |
| **P1-2.3** SEO | 0.25 | SEO +17% | 🟡 MEDIUM | ⭐⭐⭐⭐ |
| **P2-3.1** bfcache | 1 | Instant back/forward | 🟢 LOW | ⭐⭐ |
| **P2-3.2** CSS Purge | 0.5 | LCP -50ms | 🟢 LOW | ⭐⭐ |

### Total Investment
- **Sprint 1 (P0)**: 6-9 days → Performance 48 → 70-75
- **Sprint 2 (P0+P1)**: 12-14 days → Performance 70-75 → 85-90
- **Sprint 3 (P2)**: 15-16 days → Performance 85-90 → >90

**Recommended Approach**: Focus on Sprint 1-2 (P0+P1) for maximum ROI

---

## Appendix: Technical Details

### A. Current Bundle Analysis Needed
```bash
# Run to identify specific issues
npm install --save-dev webpack-bundle-analyzer
npm run build -- --analyze

# Check for:
# - Duplicate dependencies (lodash, moment, date-fns)
# - Unused Chainlit features
# - Heavy markdown/code highlighting libraries
```

### B. Critical CSS Extraction
```javascript
// Use critical package
import { generate } from 'critical';

generate({
  inline: true,
  base: 'dist/',
  src: 'index.html',
  target: 'index-critical.html',
  width: 1300,
  height: 900
});
```

### C. Font Optimization
```css
/* Use variable font instead of multiple weights */
@font-face {
  font-family: 'Inter';
  src: url('/fonts/Inter-var.woff2') format('woff2-variations');
  font-weight: 100 900;
  font-display: swap;
}
```

### D. Service Worker Caching Strategy
```javascript
// workbox-config.js
module.exports = {
  runtimeCaching: [
    {
      urlPattern: /^https:\/\/cwe\.crashedmind\.com\/assets\//,
      handler: 'CacheFirst',
      options: {
        cacheName: 'static-assets',
        expiration: {
          maxEntries: 50,
          maxAgeSeconds: 30 * 24 * 60 * 60, // 30 days
        },
      },
    },
  ],
};
```

---

## Next Steps

1. **Immediate Actions** (This Week):
   - Review and approve this optimization plan
   - Set up Lighthouse CI for automated tracking
   - Schedule Sprint 1 kickoff meeting
   - Assign technical lead for optimization work

2. **Sprint 1 Preparation**:
   - Create feature branch: `feat/performance-optimization`
   - Set up staging environment for testing
   - Configure Cloud Run traffic splitting (90% prod, 10% staging)
   - Create monitoring dashboard for Core Web Vitals

3. **Communication Plan**:
   - Weekly progress updates to stakeholders
   - Daily Slack updates on critical metrics
   - Post-sprint retrospective and performance review

---

**Document Version**: 1.0
**Last Updated**: October 21, 2025
**Owner**: DevOps/Performance Team
**Next Review**: After Sprint 1 completion
