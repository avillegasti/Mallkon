export const REQUIRED_RELEASE_LAYER_NAMES = [
  "meta-northfi-distro",
  "meta-arquimea-distro-base",
  "meta-layout-base",
  "meta-arquimea-security",
];

export const REVIEW_STORAGE_KEY = "northfi.releaseReviews.v1";
export const REVIEW_ACTOR_STORAGE_KEY = "northfi.currentReviewer";

export const RELEASE_REVIEW_CHECKS = [
  ["cve_reviewed", "CVEs reviewed", "Open CVEs were inspected and accepted or assigned."],
  ["full_cve_export_reviewed", "Full CVE export reviewed", "CSV/JSON export was generated and reviewed."],
  ["artifacts_verified", "Artifacts verified", "Boot, WIC, BMAP, and SWU artifacts are present."],
  ["flashing_tested", "Flashing tested", "Image was flashed or test evidence was attached."],
  ["dev_origins_confirmed", "Dev origins confirmed", "Linked development builds match the released tag."],
  ["layer_tags_verified", "Layer tags verified", "Required release layer tags are present."],
  ["regression_reviewed", "Regression reviewed", "Latest-vs-previous regression alerts were checked."],
  ["jira_linked", "Jira linked", "Optional release or security tracking ticket is linked."],
];

export const OPTIONAL_RELEASE_REVIEW_CHECKS = new Set(["jira_linked"]);
