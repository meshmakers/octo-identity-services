import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable, of } from 'rxjs';
import { catchError, map, tap } from 'rxjs/operators';
import { UserProfile } from '../models/manage.models';

export interface AuthState {
  isAuthenticated: boolean;
  user?: UserProfile;
  loading: boolean;
}

@Injectable({ providedIn: 'root' })
export class AuthStateService {
  private http = inject(HttpClient);

  private state = new BehaviorSubject<AuthState>({
    isAuthenticated: false,
    loading: true
  });

  readonly authState$ = this.state.asObservable();
  readonly isAuthenticated$ = this.state.pipe(map(s => s.isAuthenticated));
  readonly user$ = this.state.pipe(map(s => s.user));
  readonly loading$ = this.state.pipe(map(s => s.loading));

  get currentUser(): UserProfile | undefined {
    return this.state.value.user;
  }

  get isAuthenticated(): boolean {
    return this.state.value.isAuthenticated;
  }

  /**
   * Check authentication status by trying to load the user profile
   */
  checkAuthStatus(): Observable<boolean> {
    this.state.next({ ...this.state.value, loading: true });

    return this.http.get<UserProfile>('/api/manage/profile').pipe(
      tap(user => {
        this.state.next({
          isAuthenticated: true,
          user,
          loading: false
        });
      }),
      map(() => true),
      catchError(() => {
        this.state.next({
          isAuthenticated: false,
          user: undefined,
          loading: false
        });
        return of(false);
      })
    );
  }

  /**
   * Clear auth state (call after logout)
   */
  clearAuthState(): void {
    this.state.next({
      isAuthenticated: false,
      user: undefined,
      loading: false
    });
  }

  /**
   * Update auth state after successful login
   */
  setAuthenticated(user: UserProfile): void {
    this.state.next({
      isAuthenticated: true,
      user,
      loading: false
    });
  }
}
