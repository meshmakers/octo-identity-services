import { Component, Input, Output, EventEmitter, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ScopeItem } from '../../../core/models/consent.models';

@Component({
  selector: 'app-scope-list',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="lcars-scope-list">
      <div class="lcars-scope-list__header" *ngIf="title">
        {{ title }}
      </div>
      <div class="lcars-scope-list__items">
        <div
          *ngFor="let scope of scopes"
          class="lcars-scope-item"
          [class.lcars-scope-item--emphasized]="scope.emphasize">
          <input
            type="checkbox"
            [id]="'scope-' + scope.name"
            [(ngModel)]="scope.checked"
            [disabled]="scope.required"
            (ngModelChange)="onScopeChange()"
            class="lcars-checkbox" />
          <label [for]="'scope-' + scope.name" class="lcars-scope-item__content">
            <span class="lcars-scope-item__name">
              {{ scope.displayName }}
              <span *ngIf="scope.required" class="lcars-scope-item__required">Required</span>
            </span>
            <span *ngIf="scope.description" class="lcars-scope-item__description">
              {{ scope.description }}
            </span>
          </label>
        </div>
      </div>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.Eager,
  styleUrl: './scope-list.component.scss'
})
export class ScopeListComponent {
  @Input() title?: string;
  @Input() scopes: ScopeItem[] = [];
  @Output() scopesChange = new EventEmitter<ScopeItem[]>();

  onScopeChange(): void {
    this.scopesChange.emit(this.scopes);
  }
}
