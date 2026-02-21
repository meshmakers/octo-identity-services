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

export interface DeviceAuthorizationResult {
  success: boolean;
  errorMessage?: string;
}
