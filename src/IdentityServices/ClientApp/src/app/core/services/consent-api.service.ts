import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import {
  ConsentContext,
  ConsentRequest,
  ConsentResult,
  DeviceAuthorizationContext,
  DeviceAuthorizationRequest,
  DeviceAuthorizationResult
} from '../models/consent.models';

@Injectable({ providedIn: 'root' })
export class ConsentApiService {
  private http = inject(HttpClient);

  // === Consent ===

  getConsentContext(returnUrl: string): Observable<ConsentContext> {
    return this.http.get<ConsentContext>('/api/consent', {
      params: { returnUrl }
    });
  }

  grantConsent(request: ConsentRequest): Observable<ConsentResult> {
    return this.http.post<ConsentResult>('/api/consent/grant', request);
  }

  denyConsent(returnUrl: string): Observable<ConsentResult> {
    return this.http.post<ConsentResult>('/api/consent/deny', { returnUrl });
  }

  // === Device Authorization ===

  getDeviceAuthorizationContext(userCode: string): Observable<DeviceAuthorizationContext> {
    return this.http.get<DeviceAuthorizationContext>('/api/device', {
      params: { userCode }
    });
  }

  submitDeviceAuthorization(request: DeviceAuthorizationRequest): Observable<DeviceAuthorizationResult> {
    return this.http.post<DeviceAuthorizationResult>('/api/device/authorize', request);
  }

  denyDeviceAuthorization(userCode: string): Observable<DeviceAuthorizationResult> {
    return this.http.post<DeviceAuthorizationResult>('/api/device/deny', { userCode });
  }
}
