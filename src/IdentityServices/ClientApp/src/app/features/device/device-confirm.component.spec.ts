import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, Router } from '@angular/router';
import { HttpErrorResponse } from '@angular/common/http';
import { provideTranslateService, TranslateService } from '@ngx-translate/core';
import { of, throwError } from 'rxjs';
import { DeviceConfirmComponent } from './device-confirm.component';
import { ConsentApiService } from '../../core/services/consent-api.service';
import { DeviceAuthorizationContext } from '../../core/models/consent.models';

describe('DeviceConfirmComponent (AB#6993 login loop guard)', () => {
  const navigate = vi.fn();
  const getContext = vi.fn();

  beforeEach(() => {
    TestBed.resetTestingModule();
    navigate.mockReset();
    getContext.mockReset();
  });

  function create(queryParams: Record<string, string>) {
    TestBed.configureTestingModule({
      imports: [DeviceConfirmComponent],
      providers: [
        provideTranslateService(),
        { provide: Router, useValue: { navigate } },
        { provide: ConsentApiService, useValue: { getDeviceAuthorizationContext: getContext } },
        {
          provide: ActivatedRoute,
          useValue: { snapshot: { queryParams, params: { tenantId: 'octosystem' } } }
        }
      ]
    });
    const translate = TestBed.inject(TranslateService);
    translate.setTranslation('en', {
      DEVICE: { ERROR_SESSION_REJECTED: 'session rejected', INVALID_CODE: 'invalid code' }
    });
    translate.use('en');

    return TestBed.createComponent(DeviceConfirmComponent);
  }

  const unauthorized = () => throwError(() => new HttpErrorResponse({ status: 401 }));

  it('sends the user to the login page once on a first 401, marking the return URL', () => {
    getContext.mockReturnValue(unauthorized());
    const fixture = create({ userCode: 'ABCD-1234' });

    fixture.detectChanges();

    expect(navigate).toHaveBeenCalledTimes(1);
    const [commands, extras] = navigate.mock.calls[0];
    expect(commands).toEqual(['/', 'octosystem', 'login']);
    expect(extras.queryParams.returnUrl).toBe(
      '/octosystem/device/confirm?userCode=ABCD-1234&loginAttempted=1'
    );
  });

  it('stops with an error state when the 401 repeats after the login round trip', () => {
    getContext.mockReturnValue(unauthorized());
    const fixture = create({ userCode: 'ABCD-1234', loginAttempted: '1' });

    fixture.detectChanges();

    expect(navigate).not.toHaveBeenCalled();
    const component = fixture.componentInstance;
    expect(component.loading).toBe(false);
    expect(component.context).toBeUndefined();
    expect(component.errorMessage).toBe('session rejected');
    expect(fixture.nativeElement.textContent).toContain('session rejected');
  });

  it('ends a simulated login <-> confirm ping-pong after at most one round trip', () => {
    // The login page sends an "already signed in" user straight back to the returnUrl, so the
    // confirm page is loaded again with the marker the first navigation put into that URL.
    getContext.mockReturnValue(unauthorized());
    let query: Record<string, string> = { userCode: 'ABCD-1234' };
    let confirmLoads = 0;

    for (let i = 0; i < 10; i++) {
      navigate.mockReset();
      const fixture = create(query);
      fixture.detectChanges();
      confirmLoads++;
      if (navigate.mock.calls.length === 0) break;
      const returnUrl: string = navigate.mock.calls[0][1].queryParams.returnUrl;
      query = Object.fromEntries(new URL(returnUrl, 'https://identity.local').searchParams);
      TestBed.resetTestingModule();
    }

    expect(confirmLoads).toBe(2);
    expect(navigate).not.toHaveBeenCalled();
  });

  it('shows the device context when the verification succeeds', () => {
    const context = {
      userCode: 'ABCD-1234',
      clientName: 'octo-cli',
      identityScopes: [],
      apiScopes: []
    } as unknown as DeviceAuthorizationContext;
    getContext.mockReturnValue(of(context));
    const fixture = create({ userCode: 'ABCD-1234', loginAttempted: '1' });

    fixture.detectChanges();

    expect(navigate).not.toHaveBeenCalled();
    expect(fixture.componentInstance.context).toBe(context);
    expect(fixture.componentInstance.errorMessage).toBeUndefined();
  });

  it('shows the invalid-code fallback for a non-401 error', () => {
    getContext.mockReturnValue(throwError(() => new HttpErrorResponse({ status: 404 })));
    const fixture = create({ userCode: 'ABCD-1234' });

    fixture.detectChanges();

    expect(navigate).not.toHaveBeenCalled();
    expect(fixture.componentInstance.errorMessage).toBe('invalid code');
  });
});
