import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, Router } from '@angular/router';
import { HttpErrorResponse } from '@angular/common/http';
import { provideTranslateService, TranslateService } from '@ngx-translate/core';
import { of, throwError } from 'rxjs';
import { CROSS_TENANT_SOURCE_NOT_ANCESTOR, LoginComponent } from './login.component';
import { AuthApiService } from '../../core/services/auth-api.service';
import { ExternalProvider, LoginContext } from '../../core/models/login.models';

/**
 * AB#8367: a tenant switch the tenant registry refuses (403 with the problem code from the source tenant's
 * cross-tenant-token endpoint) is final. The login page names the reason at once instead of treating it like a missing
 * session and sending the user through the source tenant's login first. Every other refusal keeps its old path.
 */
describe('LoginComponent cross-tenant refusal (AB#8367)', () => {
  const getLoginContext = vi.fn();
  const getCrossTenantToken = vi.fn();
  const crossTenantLogin = vi.fn();

  const parent: ExternalProvider = {
    scheme: 'octo-tenant-ec-apphost',
    displayName: 'Login via ec-apphost',
    isLdap: false,
    isParentTenant: true
  };

  const context = (providers: ExternalProvider[]): LoginContext => ({
    returnUrl: '',
    externalProviders: providers,
    allowRememberLogin: true,
    enableLocalLogin: true,
    isAuthenticated: false,
    setupRequired: false,
    tenantUnavailable: false
  });

  const registryRefusal = () => new HttpErrorResponse({
    status: 403,
    error: { status: 403, title: 'The source tenant is not an ancestor of the target tenant', code: CROSS_TENANT_SOURCE_NOT_ANCESTOR }
  });

  beforeEach(() => {
    TestBed.resetTestingModule();
    getLoginContext.mockReset();
    getCrossTenantToken.mockReset();
    crossTenantLogin.mockReset();
  });

  function create(queryParams: Record<string, string>, loginContext: LoginContext) {
    getLoginContext.mockReturnValue(of(loginContext));
    TestBed.configureTestingModule({
      imports: [LoginComponent],
      providers: [
        provideTranslateService(),
        { provide: Router, useValue: { navigate: vi.fn() } },
        { provide: AuthApiService, useValue: { getLoginContext, getCrossTenantToken, crossTenantLogin } },
        { provide: ActivatedRoute, useValue: { snapshot: { queryParams, params: { tenantId: 'mrotest' } } } }
      ]
    });
    const translate = TestBed.inject(TranslateService);
    translate.setTranslation('en', {
      LOGIN: {
        ERROR_CROSS_TENANT: 'cross-tenant failed',
        ERROR_CROSS_TENANT_NOT_ALLOWED: 'mrotest does not accept sign-in from {{tenant}}'
      }
    });
    translate.use('en');

    const fixture = TestBed.createComponent(LoginComponent);
    fixture.detectChanges();
    return fixture;
  }

  const text = (fixture: { nativeElement: HTMLElement }) => fixture.nativeElement.textContent ?? '';

  it('shows the reason at once when the provider button is refused by the registry', () => {
    getCrossTenantToken.mockReturnValue(throwError(() => registryRefusal()));
    const fixture = create({}, context([parent, { ...parent, scheme: 'octo-tenant-octosystem' }]));

    fixture.componentInstance.onExternalLogin(parent);
    fixture.detectChanges();

    expect(getCrossTenantToken).toHaveBeenCalledExactlyOnceWith('ec-apphost', 'mrotest');
    expect(fixture.componentInstance.submitting).toBe(false);
    expect(text(fixture)).toContain('mrotest does not accept sign-in from ec-apphost');
    expect(crossTenantLogin).not.toHaveBeenCalled();
  });

  it('shows the reason when the quiet hand-off to the sole parent is refused by the registry', () => {
    getCrossTenantToken.mockReturnValue(throwError(() => registryRefusal()));
    const fixture = create({ returnUrl: '/connect/authorize?client_id=x' }, context([parent]));

    expect(getCrossTenantToken).toHaveBeenCalledTimes(1);
    expect(fixture.componentInstance.loading).toBe(false);
    expect(text(fixture)).toContain('mrotest does not accept sign-in from ec-apphost');
  });

  it.each([
    ['401 without a session in the parent', new HttpErrorResponse({ status: 401 })],
    ['plain 403 (second factor missing)', new HttpErrorResponse({ status: 403 })],
    ['403 with another problem code', new HttpErrorResponse({ status: 403, error: { code: 'Other' } })]
  ])('keeps the old path for a %s', (_name, error) => {
    // xtBounced=1: the user already went through the parent's login once, so the old path ends in the generic error
    // instead of a navigation.
    getCrossTenantToken.mockReturnValue(throwError(() => error));
    const fixture = create({ xtBounced: '1' }, context([parent, { ...parent, scheme: 'octo-tenant-octosystem' }]));

    fixture.componentInstance.onExternalLogin(parent);
    fixture.detectChanges();

    expect(text(fixture)).toContain('cross-tenant failed');
    expect(text(fixture)).not.toContain('does not accept sign-in');
  });
});
