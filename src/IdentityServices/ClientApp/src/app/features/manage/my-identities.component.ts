import { Component, OnInit, inject, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ManageApiService } from '../../core/services/manage-api.service';
import {
  VerifiedIdentifier,
  VerifiedIdentifierKind,
  EnrollmentTrust,
  IdentifierSource
} from '../../core/models/manage.models';

/**
 * "Meine Identitäten" tab (AB#5135 / AB#5123, "Strang B" of Epic AB#4979): the signed-in user
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
 * on an EntraID login) are shown READ-ONLY: no Remove button, a "verwaltet über Identity Provider"
 * note instead.
 */
@Component({
  selector: 'app-my-identities',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './my-identities.component.html',
  changeDetection: ChangeDetectionStrategy.Eager,
  styleUrl: './my-identities.component.scss'
})
export class MyIdentitiesComponent implements OnInit {
  private manageApi = inject(ManageApiService);

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
        this.setError('Die Identitäten konnten nicht geladen werden.');
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
            this.setSuccess('Ein Code wurde an die Telefonnummer gesendet.');
            break;
          case 'InvalidNumber':
            this.setError('Die Telefonnummer ist ungültig.');
            break;
          case 'AlreadyOwnedByAnotherUser':
            this.setError('Diese Telefonnummer ist bereits einem anderen Benutzer zugeordnet.');
            break;
          default:
            this.setError('Der Code konnte nicht gesendet werden.');
        }
      },
      error: () => {
        this.phoneSending = false;
        this.setError('Der Code konnte nicht gesendet werden.');
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
            this.setSuccess('Die Telefonnummer wurde bestätigt.');
            this.resetPhoneWizard();
            this.phoneNumber = '';
            this.reload();
            break;
          case 'CodeMismatch':
            this.phoneAttemptsRemaining = result.attemptsRemaining;
            this.setError(`Der Code ist falsch. Verbleibende Versuche: ${result.attemptsRemaining}.`);
            break;
          case 'Expired':
            this.setError('Der Code ist abgelaufen. Bitte fordern Sie einen neuen an.');
            this.resetPhoneWizard();
            break;
          case 'AttemptLimitReached':
            this.setError('Die maximale Anzahl an Versuchen wurde erreicht. Bitte fordern Sie einen neuen Code an.');
            this.resetPhoneWizard();
            break;
          case 'NoChallenge':
            this.setError('Es liegt keine offene Anfrage vor. Bitte fordern Sie einen neuen Code an.');
            this.resetPhoneWizard();
            break;
          case 'AlreadyOwnedByAnotherUser':
            this.setError('Diese Telefonnummer ist bereits einem anderen Benutzer zugeordnet.');
            this.resetPhoneWizard();
            break;
          default:
            this.setError('Die Bestätigung ist fehlgeschlagen.');
        }
      },
      error: () => {
        this.phoneVerifying = false;
        this.setError('Die Bestätigung ist fehlgeschlagen.');
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
            this.setSuccess('Ein Code wurde an die E-Mail-Adresse gesendet.');
            break;
          case 'InvalidEmail':
            this.setError('Die E-Mail-Adresse ist ungültig.');
            break;
          case 'AlreadyOwnedByAnotherUser':
            this.setError('Diese E-Mail-Adresse ist bereits einem anderen Benutzer zugeordnet.');
            break;
          default:
            this.setError('Der Code konnte nicht gesendet werden.');
        }
      },
      error: () => {
        this.emailSending = false;
        this.setError('Der Code konnte nicht gesendet werden.');
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
            this.setSuccess('Die E-Mail-Adresse wurde bestätigt.');
            this.resetEmailWizard();
            this.email = '';
            this.reload();
            break;
          case 'CodeMismatch':
            this.emailAttemptsRemaining = result.attemptsRemaining;
            this.setError(`Der Code ist falsch. Verbleibende Versuche: ${result.attemptsRemaining}.`);
            break;
          case 'Expired':
            this.setError('Der Code ist abgelaufen. Bitte fordern Sie einen neuen an.');
            this.resetEmailWizard();
            break;
          case 'AttemptLimitReached':
            this.setError('Die maximale Anzahl an Versuchen wurde erreicht. Bitte fordern Sie einen neuen Code an.');
            this.resetEmailWizard();
            break;
          case 'NoChallenge':
            this.setError('Es liegt keine offene Anfrage vor. Bitte fordern Sie einen neuen Code an.');
            this.resetEmailWizard();
            break;
          case 'AlreadyOwnedByAnotherUser':
            this.setError('Diese E-Mail-Adresse ist bereits einem anderen Benutzer zugeordnet.');
            this.resetEmailWizard();
            break;
          default:
            this.setError('Die Bestätigung ist fehlgeschlagen.');
        }
      },
      error: () => {
        this.emailVerifying = false;
        this.setError('Die Bestätigung ist fehlgeschlagen.');
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
            this.setSuccess('Das Zertifikat wurde hinzugefügt.');
            this.certificateBase64 = '';
            this.certificateFileName = '';
            this.reload();
            break;
          case 'Unreadable':
            this.setError('Die Datei konnte nicht als Zertifikat gelesen werden.');
            break;
          case 'NotValid':
            this.setError('Das Zertifikat ist nicht gültig (abgelaufen oder noch nicht gültig).');
            break;
          case 'AlreadyOwnedByAnotherUser':
            this.setError('Dieses Zertifikat ist bereits einem anderen Benutzer zugeordnet.');
            break;
          default:
            this.setError('Das Zertifikat konnte nicht hinzugefügt werden.');
        }
      },
      error: () => {
        this.enrollingCertificate = false;
        this.setError('Das Zertifikat konnte nicht hinzugefügt werden.');
      }
    });
  }

  // === Remove ===

  removeIdentifier(item: VerifiedIdentifier): void {
    if (this.isReadOnly(item)) {
      return;
    }
    const confirmed = window.confirm(`Identität "${item.identifierValue}" wirklich entfernen?`);
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
            this.setSuccess('Die Identität wurde entfernt.');
            this.reload();
          } else {
            this.setError('Die Identität konnte nicht entfernt werden.');
          }
        },
        error: () => {
          this.removingRtId = null;
          this.setError('Die Identität konnte nicht entfernt werden.');
        }
      });
  }

  // === Labels ===

  kindLabel(kind: VerifiedIdentifierKind): string {
    switch (kind) {
      case 'PhoneNumber': return 'Telefonnummer';
      case 'EmailAddress': return 'E-Mail-Adresse';
      case 'EntraIdObjectId': return 'EntraID / Teams';
      case 'ClientCertificateFingerprint': return 'Zertifikat';
      default: return kind;
    }
  }

  trustLabel(trust: EnrollmentTrust): string {
    switch (trust) {
      case 'Strong': return 'Stark';
      case 'Weak': return 'Schwach';
      case 'None': return 'Keine';
      default: return trust;
    }
  }

  sourceLabel(source: IdentifierSource): string {
    switch (source) {
      case 'SelfService': return 'Selbst hinzugefügt';
      case 'Admin': return 'Administrator';
      case 'IdentityProvider': return 'Identity Provider';
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
