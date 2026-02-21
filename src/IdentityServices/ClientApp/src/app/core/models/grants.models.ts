export interface GrantInfo {
  clientId: string;
  clientName?: string;
  clientUrl?: string;
  clientLogoUrl?: string;
  description?: string;
  created: string;
  expires?: string;
  identityGrantNames: string[];
  apiGrantNames: string[];
}

export interface RevokeGrantRequest {
  clientId: string;
}

export interface RevokeGrantResult {
  success: boolean;
  errorMessage?: string;
}
