import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ConsentApiService } from './consent-api.service';

/**
 * AB#7891: every call of the device page to /connect/deviceverification names the page's tenant as
 * acr_values=tenant:{tenantId}. The backend has no server-side user_code → tenant state any more; without
 * the hint the request would run in the system tenant on every identity replica.
 */
describe('ConsentApiService device verification tenant hint (AB#7891)', () => {
  let service: ConsentApiService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()]
    });
    service = TestBed.inject(ConsentApiService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('sends the tenant hint as a query parameter on GET', () => {
    service.getDeviceAuthorizationContext('ABCD-1234', 'child-a').subscribe();

    const request = http.expectOne(r => r.url === '/connect/deviceverification');
    expect(request.request.method).toBe('GET');
    expect(request.request.params.get('user_code')).toBe('ABCD-1234');
    expect(request.request.params.get('acr_values')).toBe('tenant:child-a');
    request.flush({});
  });

  it('sends the tenant hint in the form body on approve', () => {
    service.submitDeviceAuthorization(
      { userCode: 'ABCD-1234', scopesConsented: ['openid'], rememberConsent: false }, 'child-a').subscribe();

    const request = http.expectOne('/connect/deviceverification');
    expect(request.request.method).toBe('POST');
    const body = request.request.body.toString();
    expect(body).toContain('user_code=ABCD-1234');
    expect(body).toContain('acr_values=tenant:child-a');
    expect(body).toContain('scopes_consented=openid');
    request.flush({ success: true });
  });

  it('sends the tenant hint in the form body on deny', () => {
    service.denyDeviceAuthorization('ABCD-1234', 'child-a').subscribe();

    const request = http.expectOne('/connect/deviceverification');
    const body = request.request.body.toString();
    expect(body).toContain('deny=true');
    expect(body).toContain('acr_values=tenant:child-a');
    request.flush({ success: false, error: 'access_denied' });
  });
});
