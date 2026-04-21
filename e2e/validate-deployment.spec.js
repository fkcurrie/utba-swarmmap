const { test, expect } = require('@playwright/test');

test.describe('Deployment Validation', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application URL using the baseURL from playwright.config.js
    await page.goto('/');
  });

  test('page title is correct', async ({ page }) => {
    await expect(page).toHaveTitle(/UTBA Swarm Map/i);
  });

  test('deployment validation - basic elements', async ({ page }) => {
    // Check for the main heading
    await expect(page.locator('h1')).toContainText(/Live Swarm Tracking/i);

    // Check for the map container
    const map = page.locator('#map');
    await expect(map).toBeVisible();

    // Verify the map has content (Mapbox adds a canvas or we see a warning if token is missing)
    const mapboxMap = page.locator('.mapboxgl-map');
    const tokenAlert = page.locator('#map .alert-warning');
    await expect(mapboxMap.or(tokenAlert).first()).toBeVisible();

    // Check for the "Report a Swarm" button
    const reportBtn = page.locator('#reportSwarmBtn');
    await expect(reportBtn).toBeVisible();
    await expect(reportBtn).toContainText(/Report a Swarm/i);

    // Verify legend exists with correct items
    const legend = page.locator('#mapLegend');
    await expect(legend).toBeVisible();

    const expectedLegend = [
      { text: /Reported/i, color: 'rgb(232, 65, 24)' }, // #e84118
      { text: /Verified/i, color: 'rgb(251, 197, 49)' }, // #fbc531
      { text: /Claimed/i, color: 'rgb(255, 140, 0)' },   // #ff8c00
      { text: /Captured/i, color: 'rgb(76, 209, 55)' }, // #4cd137
      { text: /Archived/i, color: 'rgb(72, 126, 176)' } // #487eb0
    ];

    for (const item of expectedLegend) {
      const legendItem = legend.locator('.legend-item', { hasText: item.text });
      await expect(legendItem).toBeVisible();
      const colorBox = legendItem.locator('.legend-color');
      await expect(colorBox).toHaveCSS('background-color', item.color);
    }
  });

  test('report swarm modal opens and has media buttons', async ({ page }) => {
    // Click the report button to open the modal
    await page.click('#reportSwarmBtn');

    // Wait for the modal to be visible
    const modal = page.locator('#reportSwarmModal');
    await expect(modal).toBeVisible();

    // Verify modal elements
    await expect(modal.locator('.modal-title')).toContainText(/Report a New Swarm/i);
    await expect(modal.locator('#reportSwarmForm')).toBeVisible();

    // Verify media upload buttons (Camera and Video)
    const cameraBtn = modal.locator('#cameraBtn');
    await expect(cameraBtn).toBeVisible();
    await expect(cameraBtn).toContainText(/Camera/i);

    const videoBtn = modal.locator('#videoBtn');
    await expect(videoBtn).toBeVisible();
    await expect(videoBtn).toContainText(/Video/i);

    // Close the modal
    await page.click('#reportSwarmModal .btn-close');
    await expect(modal).not.toBeVisible();
  });

  test('navigation links are functional', async ({ page }) => {
    // Check navbar links
    const dashboardLink = page.locator('.navbar-nav .nav-link', { hasText: /Dashboard/i });
    if (await dashboardLink.isVisible()) {
      await dashboardLink.click();
      await expect(page).toHaveURL(/.*dashboard/);
      await page.goBack();
    }

    const loginLink = page.locator('.navbar-nav .nav-link', { hasText: /Login/i });
    if (await loginLink.isVisible()) {
      await loginLink.click();
      await expect(page).toHaveURL(/.*login/);
    }
  });
});
