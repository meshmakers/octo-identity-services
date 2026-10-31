import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, Router } from '@angular/router';
import { provideTranslateService, TranslateService } from '@ngx-translate/core';
import { of } from 'rxjs';
import { DeviceConfirmComponent } from './device-confirm.component';
import { ConsentApiService } from '../../core/services/consent-api.service';
import { DeviceAuthorizationContext } from '../../core/models/consent.models';

describe('DeviceConfirmComponent (AB#7959 target tenant and account)', () => {
  const getContext = vi.fn();

  beforeEach(() => {
    TestBed.resetTestingModule();
    getContext.mockReset();
  });

  function create(context: DeviceAuthorizationContext) {
    getContext.mockReturnValue(of(context));
    TestBed.configureTestingModule({
      imports: [DeviceConfirmComponent],
      providers: [
        provideTranslateService(),
        { provide: Router, useValue: { navigate: vi.fn() } },
        { provide: ConsentApiService, useValue: { getDeviceAuthorizationContext: getContext } },
        {
          provide: ActivatedRoute,
          useValue: { snapshot: { queryParams: { userCode: 'ABCD-1234' }, params: { tenantId: 'child-a' } } }
        }
      ]
    });
    const translate = TestBed.inject(TranslateService);
    translate.setTranslation('en', {
      DEVICE: { TARGET_TENANT: 'Tenant', SIGNED_IN_AS: 'Signed in as', CHECK_TARGET: 'check target' }
    });
    translate.use('en');

    const fixture = TestBed.createComponent(DeviceConfirmComponent);
    fixture.detectChanges();
    return fixture;
  }

  const baseContext: DeviceAuthorizationContext = {
    userCode: 'ABCD-1234',
    clientName: 'octo-cli',
    identityScopes: [],
    apiScopes: [],
    confirmUserCode: true
  };

  const text = (root: HTMLElement, selector: string) =>
    (root.querySelector(selector)?.textContent ?? '').replace(/\s+/g, ' ').trim();

  it('names the target tenant and the signed-in account next to client and user code', () => {
    const fixture = create({
      ...baseContext,
      tenantId: 'child-a',
      accountUserName: 'gerald',
      accountEmail: 'gerald@example.com'
    });
    const root: HTMLElement = fixture.nativeElement;

    expect(text(root, '[data-test="device-target-tenant"]')).toBe('child-a');
    expect(text(root, '[data-test="device-target-account"]')).toBe('gerald (gerald@example.com)');
    expect(root.textContent).toContain('Tenant');
    expect(root.textContent).toContain('Signed in as');
    expect(root.textContent).toContain('check target');
    expect(root.textContent).toContain('octo-cli');
    expect(root.textContent).toContain('ABCD-1234');
  });

  it('shows the e-mail alone when the user name is missing, and no duplicate when both are equal', () => {
    let root: HTMLElement = create({ ...baseContext, tenantId: 'child-a', accountEmail: 'g@example.com' })
      .nativeElement;
    expect(text(root, '[data-test="device-target-account"]')).toBe('g@example.com');

    TestBed.resetTestingModule();
    root = create({
      ...baseContext,
      tenantId: 'child-a',
      accountUserName: 'g@example.com',
      accountEmail: 'g@example.com'
    }).nativeElement;
    expect(text(root, '[data-test="device-target-account"]')).toBe('g@example.com');
  });

  it('renders no target block for an older server that sends neither tenant nor account', () => {
    const root: HTMLElement = create(baseContext).nativeElement;

    expect(root.querySelector('.device-target')).toBeNull();
    expect(root.textContent).toContain('octo-cli');
  });
});
