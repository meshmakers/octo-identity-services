import { Component, OnInit, inject, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { TranslatePipe, TranslateService } from '@ngx-translate/core';
import { ManageApiService } from '../../core/services/manage-api.service';
import {
  VerifiedIdentifier,
  VerifiedIdentifierKind,
  EnrollmentTrust,
  IdentifierSource,
  PreferredChannelOption
} from '../../core/models/manage.models';

/**
 * "My Identities" tab (AB#5135 / AB#5123, "Strang B" of Epic AB#4979): the signed-in user
 * manages their OWN strong channel identifiers — phone numbers and e-mail addresses (added ->
 * OTP -> verified) and client certificates — with no admin in the loop. Rendered inside
 * {@link ManageShellComponent} (inner content only).
 *
 * All calls go through {@link ManageApiService}, i.e. the SAME-ORIGIN cookie-authenticated
 * '{tenantId}/api/manage/identifiers' endpoints; the tenant prefix is added by tenantInterceptor
 * and the XSRF token by Angular's withXsrfConfiguration. This is a port of the meshmakers-app
 * page, but the cross-origin bearer used there is replaced by the ClientApp's cookie/XSRF path.
 *
 * Identifiers with source === 'IdentityProvider' (e.g. EntraID / Teams oid, created automatically
 * on an EntraID login) are shown READ-ONLY: no Remove button, a "managed via Identity Provider"
 * note instead.
 *
 * Preferred outbound channel (AB#5149, binding-specific): the user picks the CONCRETE verified
 * binding the system messages ("Microsoft Teams", "Signal (+43 ...)" per bound number) — the
 * channel kind is derived server-side from the referenced binding. The selectable options come
 * from the server (GET .../preferredChannel), never derived locally.
 */
@Component({
  selector: 'app-my-identities',
  standalone: true,
  imports: [CommonModule, FormsModule, TranslatePipe],
  templateUrl: './my-identities.component.html',
  changeDetection: ChangeDetectionStrategy.Eager,
  styleUrl: './my-identities.component.scss'
})
export class MyIdentitiesComponent implements OnInit {
  private manageApi = inject(ManageApiService);
  private translate = inject(TranslateService);

  loading = true;
  identifiers: VerifiedIdentifier[] = [];

  feedbackMessage = '';
  feedbackKind: 'success' | 'error' | null = null;

  // Phone enrolment: enter number -> (code sent) -> enter code.
  phoneNumber = '';
  phoneCode = '';
  phoneCodeSent = false;
  phoneMaskedDestination = '';
  phoneSending = false;
  phoneVerifying = false;
  phoneAttemptsRemaining: number | null = null;

  // E-mail enrolment: enter address -> (code sent) -> enter code.
  email = '';
  emailCode = '';
  emailCodeSent = false;
  emailMaskedDestination = '';
  emailSending = false;
  emailVerifying = false;
  emailAttemptsRemaining: number | null = null;

  // Certificate enrolment.
  certificateFileName = '';
  enrollingCertificate = false;
  private certificateBase64 = '';

  removingRtId: string | null = null;

  // Preferred outbound channel (AB#5149, binding-specific): which verified binding the system
  // messages for system-initiated contact. Options and the current selection are server-provided.
  preferredBindingId: string | null = null;
  preferredChannelOptions: PreferredChannelOption[] = [];
  preferredChannelLoaded = false;
  savingPreferredChannel = false;

  ngOnInit(): void {
    this.reload();
  }

  reload(): void {
    this.loading = true;
    this.manageApi.getIdentifiers().subscribe({
      next: (list) => {
        this.identifiers = list ?? [];
        this.loading = false;
      },
      error: () => {
        this.identifiers = [];
        this.loading = false;
        this.setError(this.translate.instant('MY_IDENTITIES.ERROR_LOAD'));
      }
    });
    this.reloadPreferredChannel();
  }

  // === Preferred outbound channel (AB#5149, binding-specific) ===

  private reloadPreferredChannel(): void {
    this.manageApi.getPreferredChannel().subscribe({
      next: (result) => {
        this.preferredBindingId = result.bindingId;
        this.preferredChannelOptions = result.options ?? [];
        this.preferredChannelLoaded = true;
      },
      error: () => {
        this.preferredBindingId = null;
        this.preferredChannelOptions = [];
        this.preferredChannelLoaded = true;
      }
    });
  }

  /** Display label for one option: product names stay untranslated, the target value disambiguates. */
  optionLabel(option: PreferredChannelOption): string {
    return option.channel === 'TEAMS'
      ? 'Microsoft Teams'
      : `Signal (${option.identifierValue})`;
  }

  setPreferredChannel(bindingId: string | null): void {
    if (this.savingPreferredChannel || bindingId === this.preferredBindingId) {
      return;
    }
    const previous = this.preferredBindingId;
    this.preferredBindingId = bindingId;
    this.savingPreferredChannel = true;
    this.clearFeedback();
    this.manageApi.setPreferredChannel({ bindingId }).subscribe({
      next: (result) => {
        this.savingPreferredChannel = false;
        if (result.success) {
          this.preferredBindingId = result.bindingId;
          const chosen = this.preferredChannelOptions.find((o) => o.bindingId === result.bindingId);
          this.setSuccess(
            bindingId === null || !chosen
              ? this.translate.instant('MY_IDENTITIES.PREFERRED_CHANNEL_CLEARED')
              : this.translate.instant('MY_IDENTITIES.PREFERRED_CHANNEL_SET',
                  { channel: this.optionLabel(chosen) })
          );
        } else {
          this.preferredBindingId = previous;
          this.setError(
            result.status === 'BindingNotEligible'
              ? this.translate.instant('MY_IDENTITIES.PREFERRED_CHANNEL_ERROR_NOT_ELIGIBLE')
              : this.translate.instant('MY_IDENTITIES.PREFERRED_CHANNEL_ERROR_SAVE')
          );
          // The refused binding may have expired since the options were loaded — refresh them.
          this.reloadPreferredChannel();
        }
      },
      error: () => {
        this.savingPreferredChannel = false;
        this.preferredBindingId = previous;
        this.setError(this.translate.instant('MY_IDENTITIES.PREFERRED_CHANNEL_ERROR_SAVE'));
      }
    });
  }

  isReadOnly(item: VerifiedIdentifier): boolean {
    return item.source === 'IdentityProvider';
  }

  // === Phone wizard ===

  sendPhoneCode(): void {
    const number = this.phoneNumber.trim();
    if (!number) {
      return;
    }
    this.phoneSending = true;
    this.phoneAttemptsRemaining = null;
    this.clearFeedback();
    this.manageApi.startPhoneEnrollment({ phoneNumber: number }).subscribe({
      next: (result) => {
        this.phoneSending = false;
        switch (result.status) {
          case 'CodeSent':
            this.phoneCodeSent = true;
            this.phoneMaskedDestination = result.maskedDestination ?? number;
            this.phoneCode = '';
            this.setSuccess(this.translate.instant('MY_IDENTITIES.PHONE_MSG_CODE_SENT'));
            break;
          case 'InvalidNumber':
            this.setError(this.translate.instant('MY_IDENTITIES.PHONE_ERROR_INVALID'));
            break;
          case 'AlreadyOwnedByAnotherUser':
            this.setError(this.translate.instant('MY_IDENTITIES.PHONE_ERROR_OWNED'));
            break;
          default:
            this.setError(this.translate.instant('MY_IDENTITIES.WIZARD_ERROR_SEND'));
        }
      },
      error: () => {
        this.phoneSending = false;
        this.setError(this.translate.instant('MY_IDENTITIES.WIZARD_ERROR_SEND'));
      }
    });
  }

  verifyPhoneCode(): void {
    const code = this.phoneCode.trim();
    if (!code) {
      return;
    }
    this.phoneVerifying = true;
    this.clearFeedback();
    this.manageApi.verifyPhone({ phoneNumber: this.phoneNumber.trim(), code }).subscribe({
      next: (result) => {
        this.phoneVerifying = false;
        switch (result.status) {
          case 'Verified':
            this.setSuccess(this.translate.instant('MY_IDENTITIES.PHONE_MSG_VERIFIED'));
            this.resetPhoneWizard();
            this.phoneNumber = '';
            this.reload();
            break;
          case 'CodeMismatch':
            this.phoneAttemptsRemaining = result.attemptsRemaining;
            this.setError(this.translate.instant('MY_IDENTITIES.WIZARD_ERROR_CODE_MISMATCH',
              { count: result.attemptsRemaining }));
            break;
          case 'Expired':
            this.setError(this.translate.instant('MY_IDENTITIES.WIZARD_ERROR_EXPIRED'));
            this.resetPhoneWizard();
            break;
          case 'AttemptLimitReached':
            this.setError(this.translate.instant('MY_IDENTITIES.WIZARD_ERROR_ATTEMPTS'));
            this.resetPhoneWizard();
            break;
          case 'NoChallenge':
            this.setError(this.translate.instant('MY_IDENTITIES.WIZARD_ERROR_NO_CHALLENGE'));
            this.resetPhoneWizard();
            break;
          case 'AlreadyOwnedByAnotherUser':
            this.setError(this.translate.instant('MY_IDENTITIES.PHONE_ERROR_OWNED'));
            this.resetPhoneWizard();
            break;
          default:
            this.setError(this.translate.instant('MY_IDENTITIES.WIZARD_ERROR_CONFIRM'));
        }
      },
      error: () => {
        this.phoneVerifying = false;
        this.setError(this.translate.instant('MY_IDENTITIES.WIZARD_ERROR_CONFIRM'));
      }
    });
  }

  cancelPhone(): void {
    this.resetPhoneWizard();
    this.phoneNumber = '';
    this.clearFeedback();
  }

  // === E-mail wizard ===

  sendEmailCode(): void {
    const address = this.email.trim();
    if (!address) {
      return;
    }
    this.emailSending = true;
    this.emailAttemptsRemaining = null;
    this.clearFeedback();
    this.manageApi.startEmailEnrollment({ email: address }).subscribe({
      next: (result) => {
        this.emailSending = false;
        switch (result.status) {
          case 'CodeSent':
            this.emailCodeSent = true;
            this.emailMaskedDestination = result.maskedDestination ?? address;
            this.emailCode = '';
            this.setSuccess(this.translate.instant('MY_IDENTITIES.EMAIL_MSG_CODE_SENT'));
            break;
          case 'InvalidEmail':
            this.setError(this.translate.instant('MY_IDENTITIES.EMAIL_ERROR_INVALID'));
            break;
          case 'AlreadyOwnedByAnotherUser':
            this.setError(this.translate.instant('MY_IDENTITIES.EMAIL_ERROR_OWNED'));
            break;
          default:
            this.setError(this.translate.instant('MY_IDENTITIES.WIZARD_ERROR_SEND'));
        }
      },
      error: () => {
        this.emailSending = false;
        this.setError(this.translate.instant('MY_IDENTITIES.WIZARD_ERROR_SEND'));
      }
    });
  }

  verifyEmailCode(): void {
    const code = this.emailCode.trim();
    if (!code) {
      return;
    }
    this.emailVerifying = true;
    this.clearFeedback();
    this.manageApi.verifyEmail({ email: this.email.trim(), code }).subscribe({
      next: (result) => {
        this.emailVerifying = false;
        switch (result.status) {
          case 'Verified':
            this.setSuccess(this.translate.instant('MY_IDENTITIES.EMAIL_MSG_VERIFIED'));
            this.resetEmailWizard();
            this.email = '';
            this.reload();
            break;
          case 'CodeMismatch':
            this.emailAttemptsRemaining = result.attemptsRemaining;
            this.setError(this.translate.instant('MY_IDENTITIES.WIZARD_ERROR_CODE_MISMATCH',
              { count: result.attemptsRemaining }));
            break;
          case 'Expired':
            this.setError(this.translate.instant('MY_IDENTITIES.WIZARD_ERROR_EXPIRED'));
            this.resetEmailWizard();
            break;
          case 'AttemptLimitReached':
            this.setError(this.translate.instant('MY_IDENTITIES.WIZARD_ERROR_ATTEMPTS'));
            this.resetEmailWizard();
            break;
          case 'NoChallenge':
            this.setError(this.translate.instant('MY_IDENTITIES.WIZARD_ERROR_NO_CHALLENGE'));
            this.resetEmailWizard();
            break;
          case 'AlreadyOwnedByAnotherUser':
            this.setError(this.translate.instant('MY_IDENTITIES.EMAIL_ERROR_OWNED'));
            this.resetEmailWizard();
            break;
          default:
            this.setError(this.translate.instant('MY_IDENTITIES.WIZARD_ERROR_CONFIRM'));
        }
      },
      error: () => {
        this.emailVerifying = false;
        this.setError(this.translate.instant('MY_IDENTITIES.WIZARD_ERROR_CONFIRM'));
      }
    });
  }

  cancelEmail(): void {
    this.resetEmailWizard();
    this.email = '';
    this.clearFeedback();
  }

  // === Certificate ===

  async onCertificateSelected(event: Event): Promise<void> {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) {
      return;
    }
    this.certificateFileName = file.name;
    const bytes = new Uint8Array(await file.arrayBuffer());
    let binary = '';
    for (const b of bytes) {
      binary += String.fromCharCode(b);
    }
    this.certificateBase64 = btoa(binary);
  }

  enrollCertificate(): void {
    if (!this.certificateBase64) {
      return;
    }
    this.enrollingCertificate = true;
    this.clearFeedback();
    this.manageApi.enrollCertificate({ certificateBase64: this.certificateBase64 }).subscribe({
      next: (result) => {
        this.enrollingCertificate = false;
        switch (result.status) {
          case 'Enrolled':
            this.setSuccess(this.translate.instant('MY_IDENTITIES.CERT_MSG_ADDED'));
            this.certificateBase64 = '';
            this.certificateFileName = '';
            this.reload();
            break;
          case 'Unreadable':
            this.setError(this.translate.instant('MY_IDENTITIES.CERT_ERROR_UNREADABLE'));
            break;
          case 'NotValid':
            this.setError(this.translate.instant('MY_IDENTITIES.CERT_ERROR_NOT_VALID'));
            break;
          case 'AlreadyOwnedByAnotherUser':
            this.setError(this.translate.instant('MY_IDENTITIES.CERT_ERROR_OWNED'));
            break;
          default:
            this.setError(this.translate.instant('MY_IDENTITIES.CERT_ERROR_ADD'));
        }
      },
      error: () => {
        this.enrollingCertificate = false;
        this.setError(this.translate.instant('MY_IDENTITIES.CERT_ERROR_ADD'));
      }
    });
  }

  // === Remove ===

  removeIdentifier(item: VerifiedIdentifier): void {
    if (this.isReadOnly(item)) {
      return;
    }
    const confirmed = window.confirm(
      this.translate.instant('MY_IDENTITIES.CONFIRM_REMOVE', { value: item.identifierValue }));
    if (!confirmed) {
      return;
    }
    this.removingRtId = item.rtId;
    this.clearFeedback();
    this.manageApi
      .removeIdentifier({ identifierKind: item.identifierKind, identifierValue: item.identifierValue })
      .subscribe({
        next: (result) => {
          this.removingRtId = null;
          if (result.success) {
            this.setSuccess(this.translate.instant('MY_IDENTITIES.REMOVED'));
            // Also refreshes the preferred channel: removing the preferred binding clears the
            // preference server-side in the same operation.
            this.reload();
          } else {
            this.setError(this.translate.instant('MY_IDENTITIES.ERROR_REMOVE'));
          }
        },
        error: () => {
          this.removingRtId = null;
          this.setError(this.translate.instant('MY_IDENTITIES.ERROR_REMOVE'));
        }
      });
  }

  // === Labels ===

  kindLabel(kind: VerifiedIdentifierKind): string {
    switch (kind) {
      case 'PhoneNumber': return this.translate.instant('MY_IDENTITIES.KIND_PHONE');
      case 'EmailAddress': return this.translate.instant('MY_IDENTITIES.KIND_EMAIL');
      case 'EntraIdObjectId': return this.translate.instant('MY_IDENTITIES.KIND_ENTRA');
      case 'ClientCertificateFingerprint': return this.translate.instant('MY_IDENTITIES.KIND_CERTIFICATE');
      default: return kind;
    }
  }

  trustLabel(trust: EnrollmentTrust): string {
    switch (trust) {
      case 'Strong': return this.translate.instant('MY_IDENTITIES.TRUST_STRONG');
      case 'Weak': return this.translate.instant('MY_IDENTITIES.TRUST_WEAK');
      case 'None': return this.translate.instant('MY_IDENTITIES.TRUST_NONE');
      default: return trust;
    }
  }

  sourceLabel(source: IdentifierSource): string {
    switch (source) {
      case 'SelfService': return this.translate.instant('MY_IDENTITIES.SOURCE_SELF');
      case 'Admin': return this.translate.instant('MY_IDENTITIES.SOURCE_ADMIN');
      case 'IdentityProvider': return this.translate.instant('MY_IDENTITIES.SOURCE_IDP');
      default: return source;
    }
  }

  private resetPhoneWizard(): void {
    this.phoneCodeSent = false;
    this.phoneCode = '';
    this.phoneMaskedDestination = '';
    this.phoneAttemptsRemaining = null;
  }

  private resetEmailWizard(): void {
    this.emailCodeSent = false;
    this.emailCode = '';
    this.emailMaskedDestination = '';
    this.emailAttemptsRemaining = null;
  }

  private setSuccess(message: string): void {
    this.feedbackMessage = message;
    this.feedbackKind = 'success';
  }

  private setError(message: string): void {
    this.feedbackMessage = message;
    this.feedbackKind = 'error';
  }

  private clearFeedback(): void {
    this.feedbackMessage = '';
    this.feedbackKind = null;
  }
}
