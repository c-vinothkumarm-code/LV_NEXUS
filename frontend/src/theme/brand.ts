/**
 * Product identity. Change names here; colours live in tokens.css.
 *
 * Official logos are NOT drawn or recreated by this application. Place the approved files in frontend/public/brand/:
 *   latentview-logo.svg / latentview-logo-white.svg   LatentView Analytics logo (light / dark backgrounds)
 *   lv-nexus-logo.svg   / lv-nexus-logo-white.svg     LV NEXUS product logo (light / dark backgrounds)
 * Until a file exists, the name is shown as plain text (and the product mark for LV NEXUS).
 */
export const BRAND = {
  company: 'LatentView Analytics',
  product: 'LV NEXUS',
  fullName: 'LV NEXUS by LatentView Analytics',
  tagline: 'Unified Multi-Cloud Control Plane',
  pillars: 'Governance. Security. Intelligence. FinOps.',
  description: 'Unified Multi-Cloud Governance, Security, Operations & FinOps Control Plane',
  poweredBy: 'Powered by LatentView Analytics',
  companyLogo: '/brand/latentview-logo.svg',
  companyLogoOnDark: '/brand/latentview-logo-white.svg',
  productLogo: '/brand/lv-nexus-logo.svg',
  productLogoOnDark: '/brand/lv-nexus-logo-white.svg',
} as const
