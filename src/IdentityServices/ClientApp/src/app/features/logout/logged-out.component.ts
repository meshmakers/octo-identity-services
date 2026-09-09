import { Component, inject, OnInit, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute } from '@angular/router';
import { TranslatePipe } from '@ngx-translate/core';
import { LcarsPanelComponent } from '../../shared/components/lcars-panel/lcars-panel.component';
import { LcarsHeaderComponent } from '../../shared/components/lcars-header/lcars-header.component';

@Component({
  selector: 'app-logged-out',
  standalone: true,
  imports: [CommonModule, TranslatePipe, LcarsPanelComponent, LcarsHeaderComponent],
  template: `
    <div class="lcars-auth-container">
      <app-lcars-panel variant="success">
        <app-lcars-header
          [subtitle]="'LOGGED_OUT.SUBTITLE' | translate">
        </app-lcars-header>

        <div class="logged-out-content">
          <div class="success-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
              <polyline points="22 4 12 14.01 9 11.01"></polyline>
            </svg>
          </div>

          <p class="logged-out-message">
            {{ 'LOGGED_OUT.MESSAGE' | translate }}
          </p>

          <div class="lcars-actions">
            @if (returnUri) {
              <a [href]="returnUri" class="lcars-button-primary">
                {{ 'LOGGED_OUT.RETURN_TO_APP' | translate }}
              </a>
            }
            <a [href]="'/' + tenantId + '/login'" class="lcars-button-outline">
              {{ 'LOGGED_OUT.SIGN_IN_AGAIN' | translate }}
            </a>
          </div>
        </div>
      </app-lcars-panel>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.Eager,
  styleUrl: './logged-out.component.scss'
})
export class LoggedOutComponent implements OnInit {
  private route = inject(ActivatedRoute);

  returnUri: string | null = null;

  ngOnInit(): void {
    this.returnUri = this.route.snapshot.queryParams['returnUri'] || null;
  }

  get tenantId(): string {
    return this.route.snapshot.params['tenantId'] || 'System';
  }
}
