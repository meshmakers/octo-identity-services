import { Component, inject, OnInit } from '@angular/core';
import { DOCUMENT } from '@angular/common';

/**
 * Performs a full-page redirect to the root path '/'.
 * The server redirects '/' to '/{systemTenantId}/login' based on configuration.
 * Used as a catch-all route to handle unknown paths.
 */
@Component({
  selector: 'app-root-redirect',
  standalone: true,
  template: ''
})
export class RootRedirectComponent implements OnInit {
  private document = inject(DOCUMENT);

  ngOnInit(): void {
    this.document.location.href = '/';
  }
}
