/**
 * Shape returned by `GET {tenantId}/api/auth/error-context`, mirroring
 * `ErrorContextDto` on the server.
 */
export type ErrorContextKind =
  | 'unknown'
  | 'generic'
  | 'clientNotRegistered'
  | 'invalidRedirectUri';

export interface ErrorContext {
  /** Drives which copy the page shows. */
  kind?: ErrorContextKind;
  /** Raw OAuth error code — technical details only. */
  error?: string;
  activityId?: string;
  tenantId?: string;
  clientId?: string;
  /** Display name of the client, falling back to its id. */
  clientName?: string;
  /**
   * The client's registered ClientUri — the only address safe to offer as a way
   * back. Never the redirect_uri of the failed request.
   */
  clientUrl?: string;
  clientLogoUrl?: string;

  /**
   * Legacy query-parameter fields, still produced by the external-login
   * callback (`?error=` / `?errorDescription=` / `?requestId=`).
   */
  requestId?: string;
  errorMessage?: string;
  errorDescription?: string;
}
