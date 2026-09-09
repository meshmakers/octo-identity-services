import { ApplicationConfig, provideZoneChangeDetection, APP_INITIALIZER, LOCALE_ID, inject } from '@angular/core';
import { provideRouter, withComponentInputBinding } from '@angular/router';
import { HttpClient, provideHttpClient, withInterceptors, withXsrfConfiguration } from '@angular/common/http';
import { provideAnimations } from '@angular/platform-browser/animations';
import { registerLocaleData } from '@angular/common';
import localeDe from '@angular/common/locales/de';
import { provideTranslateService, TranslateLoader, TranslationObject } from '@ngx-translate/core';
import { Observable, firstValueFrom } from 'rxjs';

import { routes } from './app.routes';
import { tenantInterceptor } from './core/interceptors/tenant.interceptor';
import { OemService } from './core/services/oem.service';
import { LanguageService } from './core/services/language.service';

registerLocaleData(localeDe);

/**
 * Loads /assets/i18n/{lang}.json — same pattern as the meshmakers-app's AppTranslationLoader
 * (custom loader over HttpClient instead of the @ngx-translate/http-loader package). The path is
 * not tenant-prefixed: tenantInterceptor only rewrites '/api/...' URLs.
 */
class AppTranslationLoader implements TranslateLoader {
  private readonly http = inject(HttpClient);

  getTranslation(lang: string): Observable<TranslationObject> {
    return this.http.get<TranslationObject>(`/assets/i18n/${lang}.json`);
  }
}

function initializeApp(): () => Promise<void> {
  const oemService = inject(OemService);
  const languageService = inject(LanguageService);
  return () =>
    Promise.all([
      firstValueFrom(oemService.loadConfig()),
      // Translations are loaded before the first component renders, so translate.instant()
      // in TypeScript code paths is always safe.
      languageService.initialize()
    ]).then(() => undefined);
}

export const appConfig: ApplicationConfig = {
  providers: [
    provideZoneChangeDetection({ eventCoalescing: true }),
    provideRouter(routes, withComponentInputBinding()),
    provideHttpClient(
      withInterceptors([tenantInterceptor]),
      withXsrfConfiguration({
        cookieName: 'XSRF-TOKEN',
        headerName: 'X-XSRF-TOKEN'
      })
    ),
    provideAnimations(),
    provideTranslateService({
      loader: {
        provide: TranslateLoader,
        useClass: AppTranslationLoader
      }
    }),
    // Angular pipes (date/number) format in the initially active language. Resolved lazily on
    // first use — after the app initializer has set the language. A runtime language switch
    // re-renders translated texts immediately; pipe formats follow on the next full load.
    {
      provide: LOCALE_ID,
      useFactory: (): string => (inject(LanguageService).currentLanguage() === 'de' ? 'de' : 'en-US')
    },
    {
      provide: APP_INITIALIZER,
      useFactory: initializeApp,
      multi: true
    }
  ]
};
