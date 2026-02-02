import { Component, Input, Output, EventEmitter } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';
import { IconDefinition } from '@fortawesome/fontawesome-svg-core';
import {
  faGoogle,
  faMicrosoft,
  faFacebook,
  faApple
} from '@fortawesome/free-brands-svg-icons';
import { faServer, faNetworkWired } from '@fortawesome/free-solid-svg-icons';
import { ExternalProvider } from '../../../core/models/login.models';

@Component({
  selector: 'app-external-provider-button',
  standalone: true,
  imports: [CommonModule, FontAwesomeModule],
  template: `
    <button
      type="button"
      class="lcars-provider-button"
      [class]="'lcars-provider-button provider-' + provider.scheme.toLowerCase()"
      (click)="onLogin()"
      [disabled]="disabled">
      <fa-icon [icon]="getIcon()"></fa-icon>
      <span>{{ provider.displayName }}</span>
    </button>
  `,
  styleUrl: './external-provider-button.component.scss'
})
export class ExternalProviderButtonComponent {
  @Input({ required: true }) provider!: ExternalProvider;
  @Input() disabled = false;
  @Output() login = new EventEmitter<ExternalProvider>();

  private iconMap: Record<string, IconDefinition> = {
    google: faGoogle,
    microsoft: faMicrosoft,
    azuread: faMicrosoft,
    facebook: faFacebook,
    apple: faApple,
    ldap: faNetworkWired,
    openldap: faNetworkWired,
    activedirectory: faNetworkWired
  };

  getIcon(): IconDefinition {
    const scheme = this.provider.scheme.toLowerCase();
    return this.iconMap[scheme] || faServer;
  }

  onLogin(): void {
    this.login.emit(this.provider);
  }
}
