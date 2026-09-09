import { Injectable, inject, signal } from '@angular/core';
import { TranslateService } from '@ngx-translate/core';
import { firstValueFrom } from 'rxjs';

export type AppLanguage = 'en' | 'de';

const STORAGE_KEY = 'identity-ui.language';

/**
 * Runtime language selection for the Identity ClientApp (AB#5137). Same ngx-translate pattern as
 * the meshmakers-app: JSON resources under /assets/i18n/{lang}.json, the browser preference decides
 * the initial language, an explicit user choice is persisted in localStorage and wins on the next
 * visit. English is the fallback for missing keys.
 */
@Injectable({ providedIn: 'root' })
export class LanguageService {
  private readonly translate = inject(TranslateService);

  static readonly supportedLanguages: readonly AppLanguage[] = ['en', 'de'];

  readonly currentLanguage = signal<AppLanguage>('en');

  /** Resolves once the initial language (persisted override -> browser -> 'en') is loaded. */
  async initialize(): Promise<void> {
    this.translate.setDefaultLang('en');
    const initial = this.readPersistedLanguage() ?? this.detectBrowserLanguage() ?? 'en';
    await firstValueFrom(this.translate.use(initial));
    this.currentLanguage.set(initial);
  }

  /** Switches the active language and persists the choice as the user's override. */
  async setLanguage(language: AppLanguage): Promise<void> {
    if (!LanguageService.supportedLanguages.includes(language)) {
      return;
    }
    try {
      localStorage.setItem(STORAGE_KEY, language);
    } catch {
      // Storage may be unavailable (private mode) — the switch still applies for this session.
    }
    if (language === this.currentLanguage()) {
      return;
    }
    await firstValueFrom(this.translate.use(language));
    this.currentLanguage.set(language);
  }

  private readPersistedLanguage(): AppLanguage | null {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      return stored === 'en' || stored === 'de' ? stored : null;
    } catch {
      return null;
    }
  }

  private detectBrowserLanguage(): AppLanguage | null {
    const candidates =
      typeof navigator !== 'undefined' ? (navigator.languages ?? [navigator.language]) : [];
    for (const candidate of candidates) {
      const prefix = candidate?.split('-')[0]?.toLowerCase();
      if (prefix === 'en' || prefix === 'de') {
        return prefix;
      }
    }
    return null;
  }
}
