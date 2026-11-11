/** Stable provider ID shared by readiness, doctor and Evidence. */
export const PARANOIA_PROVIDER_ID = "paranoia";

/** The `paranoia query` answer format this provider reads. */
export const PARANOIA_QUERY_FORMAT = "paranoia-query/1";

/** Remediation when `REA_PARANOIA_COMMAND` is missing or not an absolute path. */
export const PARANOIA_COMMAND_REMEDIATION =
  "Set REA_PARANOIA_COMMAND to the absolute path of a caller-supplied `paranoia` executable (https://github.com/Altumptic/paranoia, a release with `paranoia query`). REA does not download, install or update Paranoia.";
