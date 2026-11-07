import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
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
  //
  // AB#4993 (OpenIddict migration): the device flow is driven through the OpenIddict end-user
  // verification endpoint (/connect/deviceverification). The endpoint has no tenant route segment;
  // the page names its tenant (the /{tenantId}/device route) as acr_values=tenant:{tenantId} on
  // every call (AB#7891), so the backend validates the user code against that tenant only and any
  // identity replica can serve the request. The endpoint expects application/x-www-form-urlencoded
  // input on POST; the response DTOs are unchanged.

  private static readonly deviceVerificationUrl = '/connect/deviceverification';

  /** The tenant hint of the device verification endpoint (AB#7891). */
  static tenantHint(tenantId: string): string {
    return `tenant:${tenantId}`;
  }

  getDeviceAuthorizationContext(userCode: string, tenantId: string): Observable<DeviceAuthorizationContext> {
    return this.http.get<DeviceAuthorizationContext>(ConsentApiService.deviceVerificationUrl, {
      params: { user_code: userCode, acr_values: ConsentApiService.tenantHint(tenantId) }
    });
  }

  submitDeviceAuthorization(request: DeviceAuthorizationRequest, tenantId: string): Observable<DeviceAuthorizationResult> {
    let body = new HttpParams()
      .set('user_code', request.userCode)
      .set('acr_values', ConsentApiService.tenantHint(tenantId));
    if (request.rememberConsent !== undefined) {
      body = body.set('remember_consent', String(request.rememberConsent));
    }
    for (const scope of request.scopesConsented ?? []) {
      body = body.append('scopes_consented', scope);
    }
    return this.http.post<DeviceAuthorizationResult>(ConsentApiService.deviceVerificationUrl, body);
  }

  denyDeviceAuthorization(userCode: string, tenantId: string): Observable<DeviceAuthorizationResult> {
    const body = new HttpParams()
      .set('user_code', userCode)
      .set('deny', 'true')
      .set('acr_values', ConsentApiService.tenantHint(tenantId));
    return this.http.post<DeviceAuthorizationResult>(ConsentApiService.deviceVerificationUrl, body);
  }
}
