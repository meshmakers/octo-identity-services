export interface ScopeItem {
  name: string;
  displayName: string;
  description?: string;
  emphasize: boolean;
  required: boolean;
  checked: boolean;
}

export interface ConsentContext {
  returnUrl: string;
  clientName: string;
  clientUrl?: string;
  clientLogoUrl?: string;
  identityScopes: ScopeItem[];
  apiScopes: ScopeItem[];
  allowRememberConsent: boolean;
  description?: string;
}

export interface ConsentRequest {
  returnUrl: string;
  scopesConsented: string[];
  rememberConsent: boolean;
  description?: string;
}

export interface ConsentResult {
  success: boolean;
  redirectUrl?: string;
  errorMessage?: string;
  validationError?: string;
}

// Device authorization models
export interface DeviceAuthorizationContext {
  userCode: string;
  clientName?: string;
  clientUrl?: string;
  clientLogoUrl?: string;
  identityScopes: ScopeItem[];
  apiScopes: ScopeItem[];
  confirmUserCode: boolean;
  description?: string;
}

export interface DeviceAuthorizationRequest {
  userCode: string;
  scopesConsented: string[];
  rememberConsent: boolean;
  description?: string;
}

/**
 * Body of POST /connect/deviceverification (written by OctoDeviceVerificationResponseHandler,
 * always HTTP 200): `success` true when the user code was approved/denied by OpenIddict, otherwise
 * `error` carries the OAuth error code (invalid_token = used/expired/rejected code,
 * access_denied = denied by the user or cross-tenant access refused) and `errorMessage` the text.
 */
export interface DeviceAuthorizationResult {
  success: boolean;
  errorMessage?: string;
  error?: string;
}
