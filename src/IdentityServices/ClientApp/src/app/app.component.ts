import { Component, inject } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { OemService } from './core/services/oem.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet],
  template: `
    <div class="app-container">
      <router-outlet></router-outlet>
    </div>
  `,
  styles: [`
    .app-container {
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      background: var(--deep-sea);
    }
  `]
})
export class AppComponent {
  private oemService = inject(OemService);
  config$ = this.oemService.config;
}
