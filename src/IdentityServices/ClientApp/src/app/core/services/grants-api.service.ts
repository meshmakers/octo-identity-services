import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { GrantInfo, RevokeGrantRequest, RevokeGrantResult } from '../models/grants.models';

@Injectable({ providedIn: 'root' })
export class GrantsApiService {
  private http = inject(HttpClient);

  getGrants(): Observable<GrantInfo[]> {
    return this.http.get<GrantInfo[]>('/api/grants');
  }

  revokeGrant(request: RevokeGrantRequest): Observable<RevokeGrantResult> {
    return this.http.post<RevokeGrantResult>('/api/grants/revoke', request);
  }
}
