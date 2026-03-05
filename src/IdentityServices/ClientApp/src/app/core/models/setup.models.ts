export interface SetupStatus {
  setupRequired: boolean;
}

export interface SetupAdminRequest {
  email: string;
  password: string;
  confirmPassword: string;
}

export interface SetupResult {
  success: boolean;
  errorMessage?: string;
}
