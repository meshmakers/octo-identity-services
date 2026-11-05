import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, Router } from '@angular/router';
import { HttpErrorResponse } from '@angular/common/http';
import { provideTranslateService, TranslateService } from '@ngx-translate/core';
import { of, Subject, throwError } from 'rxjs';
import { DeviceConfirmComponent } from './device-confirm.component';
import { ConsentApiService } from '../../core/services/consent-api.service';
import {
  DeviceAuthorizationContext,
  DeviceAuthorizationResult
} from '../../core/models/consent.models';

/**
 * AB#7090: Allow / Deny must always end in a visible state — success, denied or an error —
 * never in a silent dead end on the consent dialog. The result bodies below are the real shapes
 * written by OctoDeviceVerificationResponseHandler (always HTTP 200; see its unit tests).
 */
describe('DeviceConfirmComponent feedback after Allow / Deny (AB#7090)', () => {
  const getContext = vi.fn();
  const submit = vi.fn();
  const deny = vi.fn();

  const context = {
    userCode: 'ABCD-1234',
    clientName: 'octo-cli',
    identityScopes: [{ name: 'openid', displayName: 'openid', checked: true }],
    apiScopes: [{ name: 'octo_api', displayName: 'octo_api', checked: true }],
    confirmUserCode: true
  } as unknown as DeviceAuthorizationContext;

  beforeEach(() => {
    TestBed.resetTestingModule();
    getContext.mockReset().mockReturnValue(of(context));
    submit.mockReset();
    deny.mockReset();
  });

  function create() {
    TestBed.configureTestingModule({
      imports: [DeviceConfirmComponent],
      providers: [
        provideTranslateService(),
        { provide: Router, useValue: { navigate: vi.fn() } },
        {
          provide: ConsentApiService,
          useValue: {
            getDeviceAuthorizationContext: getContext,
            submitDeviceAuthorization: submit,
            denyDeviceAuthorization: deny
          }
        },
        {
          provide: ActivatedRoute,
          useValue: { snapshot: { queryParams: { userCode: 'ABCD-1234' }, params: { tenantId: 'meshtest' } } }
        }
      ]
    });
    const translate = TestBed.inject(TranslateService);
    translate.setTranslation('en', {
      COMMON: { ERROR_GENERIC: 'generic error', ALLOW: 'Allow', DENY: 'Deny', PROCESSING: '...', TRY_AGAIN: 'again' },
      DEVICE: {
        SUCCESS: 'authorized',
        DENIED: 'denied by you',
        ERROR_AUTH_FAILED: 'auth failed',
        ERROR_CODE_USED: 'code used',
        ERROR_NO_CONFIRMATION: 'no confirmation',
        ERROR_SESSION_REJECTED: 'session rejected',
        INVALID_CODE: 'invalid code'
      }
    });
    translate.use('en');

    const fixture = TestBed.createComponent(DeviceConfirmComponent);
    fixture.detectChanges();
    return fixture;
  }

  const text = (fixture: { nativeElement: HTMLElement }) => fixture.nativeElement.textContent ?? '';
  const hasDialog = (fixture: { nativeElement: HTMLElement }) =>
    fixture.nativeElement.querySelector('.lcars-actions') !== null;

  function click(fixture: ReturnType<typeof create>, selector: string) {
    (fixture.nativeElement.querySelector(selector) as HTMLButtonElement).click();
    fixture.detectChanges();
  }

  const ok = (): DeviceAuthorizationResult => ({ success: true });

  describe('Allow', () => {
    it('shows the success state and removes the dialog on { success: true }', () => {
      submit.mockReturnValue(of(ok()));
      const fixture = create();

      click(fixture, '.lcars-button-primary');

      expect(submit).toHaveBeenCalledTimes(1);
      expect(text(fixture)).toContain('authorized');
      expect(hasDialog(fixture)).toBe(false);
    });

    it('shows a visible error and ends the dialog for a used/expired code (invalid_token)', () => {
      submit.mockReturnValue(of({ success: false, error: 'invalid_token', errorMessage: 'Invalid or expired device code' }));
      const fixture = create();

      click(fixture, '.lcars-button-primary');

      expect(text(fixture)).toContain('code used');
      expect(hasDialog(fixture)).toBe(false);
    });

    it('keeps the dialog for a retry but shows the server reason for other failures (cross-tenant denied)', () => {
      submit.mockReturnValue(of({ success: false, error: 'access_denied', errorMessage: 'Cross-tenant access denied' }));
      const fixture = create();

      click(fixture, '.lcars-button-primary');

      expect(text(fixture)).toContain('Cross-tenant access denied');
      expect(hasDialog(fixture)).toBe(true);
    });

    it('falls back to the generic auth-failed text when the server sends no message', () => {
      submit.mockReturnValue(of({ success: false }));
      const fixture = create();

      click(fixture, '.lcars-button-primary');

      expect(text(fixture)).toContain('auth failed');
    });

    it('treats a 2xx body without a boolean success as an unknown outcome, visible and not retryable', () => {
      submit.mockReturnValue(of({} as DeviceAuthorizationResult));
      const fixture = create();

      click(fixture, '.lcars-button-primary');

      expect(text(fixture)).toContain('no confirmation');
      expect(hasDialog(fixture)).toBe(false);
    });

    it('treats an unparsable 200 body (HttpErrorResponse status 200) as an unknown outcome', () => {
      submit.mockReturnValue(throwError(() => new HttpErrorResponse({ status: 200, statusText: 'OK' })));
      const fixture = create();

      click(fixture, '.lcars-button-primary');

      expect(text(fixture)).toContain('no confirmation');
      expect(hasDialog(fixture)).toBe(false);
    });

    it.each([
      [401, 'session rejected', false],
      [404, 'code used', false],
      [500, 'generic error', true]
    ])('shows a visible error for HTTP %i', (status, expected, dialogStays) => {
      submit.mockReturnValue(throwError(() => new HttpErrorResponse({ status })));
      const fixture = create();

      click(fixture, '.lcars-button-primary');

      expect(text(fixture)).toContain(expected);
      expect(hasDialog(fixture)).toBe(dialogStays);
    });

    it('clears an earlier error message when the user retries', () => {
      submit.mockReturnValueOnce(throwError(() => new HttpErrorResponse({ status: 500 })));
      submit.mockReturnValueOnce(of(ok()));
      const fixture = create();

      click(fixture, '.lcars-button-primary');
      expect(text(fixture)).toContain('generic error');
      click(fixture, '.lcars-button-primary');

      expect(text(fixture)).not.toContain('generic error');
      expect(text(fixture)).toContain('authorized');
    });
  });

  describe('Deny', () => {
    it('shows the denied state for the real deny answer { success: false, error: access_denied }', () => {
      deny.mockReturnValue(of({ success: false, error: 'access_denied', errorMessage: 'The device authorization was denied.' }));
      const fixture = create();

      click(fixture, '.lcars-button-error');

      expect(text(fixture)).toContain('denied by you');
      expect(hasDialog(fixture)).toBe(false);
    });

    it('shows a visible error when the code was not pending any more (invalid_token)', () => {
      deny.mockReturnValue(of({ success: false, error: 'invalid_token', errorMessage: 'Invalid or expired device code' }));
      const fixture = create();

      click(fixture, '.lcars-button-error');

      expect(text(fixture)).toContain('code used');
      expect(text(fixture)).not.toContain('denied by you');
    });

    it('shows a visible error when the call fails and keeps the dialog for a retry', () => {
      deny.mockReturnValue(throwError(() => new HttpErrorResponse({ status: 500 })));
      const fixture = create();

      click(fixture, '.lcars-button-error');

      expect(text(fixture)).toContain('generic error');
      expect(hasDialog(fixture)).toBe(true);
    });
  });

  it('does not submit twice while a request is in flight', () => {
    submit.mockReturnValue(new Subject<DeviceAuthorizationResult>());
    const fixture = create();

    fixture.componentInstance.onAllow();
    fixture.componentInstance.onAllow();

    expect(submit).toHaveBeenCalledTimes(1);
  });
});
