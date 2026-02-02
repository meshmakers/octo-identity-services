import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable, of, tap, catchError } from 'rxjs';
import { OemConfig, defaultOemConfig } from '../models/oem.models';

@Injectable({ providedIn: 'root' })
export class OemService {
  private http = inject(HttpClient);
  private configSubject = new BehaviorSubject<OemConfig>(defaultOemConfig);

  readonly config = this.configSubject.asObservable();

  get currentConfig(): OemConfig {
    return this.configSubject.value;
  }

  loadConfig(): Observable<OemConfig> {
    return this.http.get<OemConfig>('/api/oem/config').pipe(
      tap(config => {
        this.configSubject.next(config);
        this.applyThemeOverrides(config);
        this.updateFavicon(config.faviconUrl);
        this.updateTitle(config.appName);
      }),
      catchError(() => {
        // If API fails, use default config
        return of(defaultOemConfig);
      })
    );
  }

  private applyThemeOverrides(config: OemConfig): void {
    const root = document.documentElement;

    if (config.primaryColor) {
      root.style.setProperty('--octo-mint', config.primaryColor);
      const rgb = this.hexToRgb(config.primaryColor);
      if (rgb) {
        root.style.setProperty('--octo-mint-rgb', `${rgb.r}, ${rgb.g}, ${rgb.b}`);
      }
    }

    if (config.accentColor) {
      root.style.setProperty('--neo-cyan', config.accentColor);
      const rgb = this.hexToRgb(config.accentColor);
      if (rgb) {
        root.style.setProperty('--neo-cyan-rgb', `${rgb.r}, ${rgb.g}, ${rgb.b}`);
      }
    }
  }

  private hexToRgb(hex: string): { r: number; g: number; b: number } | null {
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return result
      ? {
          r: parseInt(result[1], 16),
          g: parseInt(result[2], 16),
          b: parseInt(result[3], 16)
        }
      : null;
  }

  private updateFavicon(url?: string): void {
    if (!url) return;

    const existingLink = document.querySelector("link[rel*='icon']") as HTMLLinkElement;
    if (existingLink) {
      existingLink.href = url;
    } else {
      const link = document.createElement('link');
      link.rel = 'icon';
      link.href = url;
      document.head.appendChild(link);
    }
  }

  private updateTitle(appName: string): void {
    document.title = appName;
  }
}
