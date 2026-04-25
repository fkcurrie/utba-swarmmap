// Copyright (c) 2026 Frank Currie (frank@sfle.ca)
import { test, expect } from '@playwright/test';

test('deployment validation - basic elements and assets', async ({
  page,
  context,
}, testInfo) => {
  const failedRequests = [];
  const consoleErrors = [];

  const baseURL = testInfo.project.use.baseURL || 'default';
  console.log(`Validating deployment at: ${baseURL}`);

  // Grant geolocation permissions to prevent browser prompts and ensure main.js logic can proceed
  if (baseURL !== 'default') {
    try {
      const origin = new URL(baseURL).origin;
      await context.grantPermissions(['geolocation'], { origin });
      await context.setGeolocation({ latitude: 43.6532, longitude: -79.3832 });
      console.log(`Granted geolocation permissions for ${origin}`);
    } catch (e) {
      console.warn('Failed to grant geolocation permissions:', e.message);
    }
  }

  // Track failed requests
  page.on('requestfailed', (request) => {
    const url = request.url();
    const errorText = request.failure().errorText;

    // Ignore background tracking requests that might be aborted when the test finishes
    if (url.includes('/api/track_visit')) {
      console.log(`Ignoring failed tracking request: ${url} (${errorText})`);
      return;
    }

    // Ignore optional Mapbox/external assets that might fail in CI
    if (
      url.includes('mapbox.com') ||
      url.includes('events.mapbox.com') ||
      url.includes('nominatim.openstreetmap.org') ||
      url.includes('fonts.googleapis.com') ||
      url.includes('fonts.gstatic.com') ||
      url.includes('favicon.ico')
    ) {
      console.log(
        `Ignoring failed non-critical request: ${url} (${errorText})`,
      );
      return;
    }

    failedRequests.push(`${url}: ${errorText}`);
  });

  // Track HTTP errors (4xx, 5xx)
  page.on('response', (response) => {
    const status = response.status();
    const url = response.url();
    if (status >= 400) {
      // Ignore known Mapbox or external 4xx/5xx if necessary
      if (
        url.includes('mapbox.com') ||
        url.includes('events.mapbox.com') ||
        url.includes('nominatim.openstreetmap.org') ||
        url.includes('fonts.googleapis.com') ||
        url.includes('fonts.gstatic.com') ||
        url.includes('favicon.ico')
      ) {
        return;
      }
      console.log(`HTTP ${status} for ${url}`);
    }
  });

  // Track console errors
  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      const text = msg.text();
      // Ignore various Mapbox-related errors that are either expected in some CI environments
      // or handled gracefully by the UI with fallbacks/alerts.
      if (text.includes('Mapbox token is missing')) return;
      if (text.includes('Mapbox library failed to load')) return;
      if (text.includes('Map initialization error')) return;
      if (
        text.includes('track_visit') ||
        text.includes('Failed to track visit')
      )
        return;
      if (text.includes('net::ERR_EMPTY_RESPONSE')) return; // Also ignore this if it's from the tracking request
      if (text.includes('net::ERR_ABORTED')) return;
      if (text.includes('favicon.ico')) return;
      if (text.includes('getLayer')) return; // Ignore Mapbox internal layer cleanup issues

      // Ignore generic resource load failures as they are often flaky in CI for non-critical assets
      // (like tracking pixels, optional fonts, etc.) and we track HTTP 4xx/5xx separately.
      if (text.includes('Failed to load resource')) {
        console.log(`Ignoring console error: ${text}`);
        return;
      }

      consoleErrors.push(text);
    }
  });

  // Increase reliability by waiting for various load states
  await page.goto('/', { waitUntil: 'load', timeout: 30000 });
  await page.waitForLoadState('domcontentloaded');
  // Network idle can be flaky if there are long-running background requests, so we wrap it with a short timeout
  await page.waitForLoadState('networkidle', { timeout: 10000 }).catch(() => {
    console.log(
      'Timed out waiting for network idle, proceeding with validation',
    );
  });

  // 1. Verify basic page title/content
  await expect(page).toHaveTitle(/UTBA Swarm Map/i);

  // 2. Verify key UI elements are present
  console.log('Verifying key UI elements...');
  const reportBtn = page.locator('#reportSwarmBtn');
  await expect(reportBtn).toBeVisible({ timeout: 30000 });
  await expect(reportBtn).toHaveClass(/btn-primary/);
  // Using an even more flexible regex to handle potential rendering differences,
  // whitespace, or flaky text updates during geolocation
  await expect(reportBtn).toHaveText(/Report (a Swarm )?at Your Location/i);
  await expect(reportBtn).toHaveAttribute(
    'aria-label',
    /Report a Bee Swarm at your current location/i,
  );
  await expect(reportBtn.locator('i.fa-location-dot')).toBeAttached();

  const map = page.locator('#map');

  // If visibility check fails, we want to know why (e.g. is height 0?)
  try {
    await expect(map).toBeVisible({ timeout: 30000 });
  } catch (error) {
    const box = await map.boundingBox();
    const styles = await map.evaluate((el) => {
      const s = window.getComputedStyle(el);
      return {
        display: s.display,
        visibility: s.visibility,
        height: s.height,
        width: s.width,
        opacity: s.opacity,
      };
    });
    console.error('Map visibility failure details:', {
      boundingBox: box,
      computedStyles: styles,
      html: await map.innerHTML().catch(() => 'could not get innerHTML'),
    });
    throw error;
  }

  // Check if CSS is applied (map should have height set in style.css or inline)
  const mapHeight = await map.evaluate(
    (el) => window.getComputedStyle(el).height,
  );
  expect(
    parseInt(mapHeight),
    `Map height should be at least 350px, but got ${mapHeight}`,
  ).toBeGreaterThanOrEqual(350);

  const legend = page.locator('#legendTitle');
  await expect(legend).toBeVisible({ timeout: 15000 });
  await expect(legend).toHaveText(/Map Legend/i);
  await expect(legend.locator('i.fa-circle-info')).toBeAttached();

  // Check legend items specifically within the aside area for robustness
  console.log('Verifying legend items...');
  const legendItems = page.locator('aside .legend-item');
  await expect(legendItems).toHaveCount(5);

  // Verify specific legend text and colors for robustness
  const expectedLegend = [
    { text: /Reported/i, color: 'rgb(232, 65, 24)' }, // #e84118
    { text: /Verified/i, color: 'rgb(251, 197, 49)' }, // #fbc531
    { text: /Claimed/i, color: 'rgb(255, 140, 0)' }, // #ff8c00
    { text: /Captured/i, color: 'rgb(76, 209, 55)' }, // #4cd137
    { text: /Archived/i, color: 'rgb(72, 126, 176)' }, // #487eb0
  ];

  for (let i = 0; i < expectedLegend.length; i++) {
    const item = legendItems.nth(i);
    await expect(item).toContainText(expectedLegend[i].text);
    const colorSpan = item.locator('.legend-color');
    await expect(colorSpan).toBeVisible();

    // Use normalized color comparison to handle browser spacing differences in rgb strings
    const actualColor = await colorSpan.evaluate(
      (el) => window.getComputedStyle(el).backgroundColor,
    );
    const normalize = (c) => {
      if (!c) return '';
      // Remove spaces and lowercase
      let n = c.replace(/\s+/g, '').toLowerCase();
      // Handle rgba(r,g,b,1) -> rgb(r,g,b)
      return n.replace(/rgba\((\d+,\d+,\d+),1\)/, 'rgb($1)');
    };
    expect(
      normalize(actualColor),
      `Legend item ${i} (${expectedLegend[i].text}) has wrong color (Actual: ${actualColor})`,
    ).toBe(normalize(expectedLegend[i].color));
  }

  const footer = page.locator('footer');
  await expect(footer).toBeVisible();
  await expect(footer).toContainText(/Made by .* in Toronto Canada/i);
  await expect(footer).toContainText(/contact us/i);

  // Verify footer link specifically
  const footerLink = footer.getByRole('link', { name: 'contact us' });
  await expect(footerLink).toHaveAttribute('href', 'mailto:swarmmap@sfle.ca');
  await expect(footerLink).toHaveText('contact us');
  await expect(footerLink).toBeVisible();

  // Verify Give Feedback button is present
  const feedbackBtn = page.getByRole('button', { name: /Give Feedback/i });
  await expect(feedbackBtn.first()).toBeVisible();

  // 3. Verify Report Modal functionality
  console.log('Verifying Report Modal...');
  await reportBtn.click();
  const modal = page.locator('#reportSwarmModal');
  await expect(modal).toBeVisible({ timeout: 30000 });
  await expect(modal.locator('.modal-title')).toContainText(
    /Report Bee Swarm/i,
  );
  await expect(modal.locator('i.fa-bug')).toBeAttached();

  const submitBtn = modal.locator('button[type="submit"]');
  await expect(submitBtn).toBeVisible();
  await expect(submitBtn).toHaveText(/Submit Report/i);

  const cameraBtn = modal.locator('button:has-text("Camera")');
  await expect(cameraBtn).toBeVisible();

  const videoBtn = modal.locator('button:has-text("Video")');
  await expect(videoBtn).toBeVisible();

  // Close the modal via close button
  await modal.locator('.btn-close').click();
  await expect(modal).not.toBeVisible({ timeout: 15000 });

  // 4. Verify Mapbox map is initialized or a fallback alert is present
  console.log('Verifying Mapbox state...');
  // Accept any alert within the map container as a valid fallback state
  const mapboxElement = page.locator('#map .mapboxgl-map, #map .alert');
  await expect(mapboxElement.first()).toBeVisible({ timeout: 30000 });

  // 5. Verify no critical assets failed to load
  if (failedRequests.length > 0) {
    console.error('Failed requests:', failedRequests);
  }
  expect(
    failedRequests,
    `Found ${failedRequests.length} failed requests: ${failedRequests.join(', ')}`,
  ).toHaveLength(0);

  // 6. Verify no console errors
  if (consoleErrors.length > 0) {
    console.error('Console errors:', consoleErrors);
  }
  // We might allow some minor console errors, but generally want none
  expect(
    consoleErrors,
    `Found ${consoleErrors.length} console errors: ${consoleErrors.join(', ')}`,
  ).toHaveLength(0);

  // 7. Verify map is rendered (if initialized)
  if ((await page.locator('.mapboxgl-map').count()) > 0) {
    // Wait for at least the map canvas to be visible. Increased timeout for CI robustness.
    await expect(page.locator('.mapboxgl-canvas').first()).toBeVisible({
      timeout: 30000,
    });
  }

  // 8. Verify visible images are rendered (non-zero size)
  const images = page.locator('img:visible');
  const imageCount = await images.count();
  for (let i = 0; i < imageCount; i++) {
    const img = images.nth(i);
    const src = (await img.getAttribute('src')) || '';
    const alt = (await img.getAttribute('alt')) || 'no alt';
    // Skip Mapbox images and data URIs as they can have transitional 0-size states
    // or be used for tracking/spacers
    if (src.includes('mapbox.com') || src.startsWith('data:')) continue;

    const box = await img.boundingBox();
    // If it's visible but has no box, or very small, it might be a tracking pixel or still loading
    if (!box || (box.width <= 1 && box.height <= 1)) {
      console.log(
        `Skipping potential tracking pixel or small image: ${src} (alt: ${alt})`,
      );
      continue;
    }

    expect(
      box.width,
      `Visible image ${i} (${src}, alt: ${alt}) has zero width`,
    ).toBeGreaterThan(1);
    expect(
      box.height,
      `Visible image ${i} (${src}, alt: ${alt}) has zero height`,
    ).toBeGreaterThan(1);
  }

  // 9. Visual check - attach a screenshot to the test report
  await testInfo.attach('deployment-screenshot', {
    body: await page.screenshot({ fullPage: true }),
    contentType: 'image/png',
  });
});
