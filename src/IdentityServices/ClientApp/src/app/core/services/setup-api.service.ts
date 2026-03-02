import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { SetupStatus, SetupAdminRequest, SetupResult } from '../models/setup.models';

@Injectable({ providedIn: 'root' })
export class SetupApiService {
  private http = inject(HttpClient);

  getSetupStatus(): Observable<SetupStatus> {
    return this.http.get<SetupStatus>('/api/setup/status');
  }

  createAdminUser(request: SetupAdminRequest): Observable<SetupResult> {
    return this.http.post<SetupResult>('/api/setup/create-admin', request);
  }
}
