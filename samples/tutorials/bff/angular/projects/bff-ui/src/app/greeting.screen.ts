import { Component } from '@angular/core';
import { GreetingsApi } from '@c4-soft/greetings-api';
import { UserService } from './user.service';

@Component({
  selector: 'app-home',
  template: `<div *ngIf="!user.current.isAuthenticated">
      <div>You are not Authenticated.</div>
      <button pButton routerLink="/login">Login</button>
    </div>
    <div *ngIf="user.current.isAuthenticated">
      <h2>Greeting (based on access token)</h2>
      <div>{{ greeting }}</div>
      <h2>ID Token</h2>
      <div>
        <div><b>subject:</b> {{ user.current.subject }}</div>
        <div><b>roles:</b> {{ user.current.roles }}</div>
        <div><b>issuer:</b> {{ user.current.issuer }}</div>
      </div>
      <button pButton type="submit" (click)="user.logout()">Logout</button>
    </div>`,
  styles: [],
})
export class GreetingScreen {
  greeting = '';

  constructor(readonly user: UserService, private greetingsApi: GreetingsApi) {}

  ngOnInit() {
    this.user.valueChanges.subscribe((u) => {
      if (!u.isAuthenticated) {
        this.greeting = '';
      } else {
        this.greetingsApi.getGreeting().subscribe({
          next: (dto) => (this.greeting = dto.message || ''),
          error: (e) => (this.greeting = e),
        });
      }
    });
  }
}
