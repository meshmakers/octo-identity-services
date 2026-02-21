import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { VERSION } from '../../../../environments/currentVersion';

@Component({
  selector: 'app-lcars-panel',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="lcars-panel" [class.lcars-panel--error]="variant === 'error'">
      <div class="lcars-panel__header"></div>
      <div class="lcars-panel__content">
        <ng-content></ng-content>
      </div>
      <div class="lcars-panel__footer">
        <div class="bar-mint"></div>
        <div class="bar-violet"></div>
        <div class="bar-toffee"></div>
        <span class="version-label">v{{ version }}</span>
      </div>
    </div>
  `,
  styleUrl: './lcars-panel.component.scss'
})
export class LcarsPanelComponent {
  @Input() variant: 'default' | 'error' | 'success' = 'default';
  protected readonly version = VERSION.version;
}
