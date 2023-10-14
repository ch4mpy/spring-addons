import { Component, OnInit } from '@angular/core';
import { LoginOptionDto, User, UserService } from './user.service';
import { HttpClient } from '@angular/common/http';
import { greetingApiUri } from './app.module';
import { lastValueFrom } from 'rxjs';

@Component({
  selector: 'app-root',
  template: `<div style="max-width: 1024;">
    <h1>Angular frontend with OAuth2 BFF</h1>
    <h2>{{ greeting }}</h2>
    <div *ngIf="currentUser.isAuthenticated">
      <h3>{{ currentUser.name }}</h3>
      <ul>
        <li *ngFor="let role of currentUser.roles">
          {{ role }}
        </li>
      </ul>
      <button (click)="logout()">Logout</button>
    </div>
    <div *ngIf="!currentUser.isAuthenticated">
      <button (click)="login()">Login</button>
    </div>
  </div>`,
  styles: [],
})
export class AppComponent implements OnInit {
  greeting: string = '';

  private loginOptions: LoginOptionDto[] = [];

  constructor(private user: UserService, private http: HttpClient) {}

  ngOnInit(): void {
    this.user.loginOptions().then((opts) => {
      this.loginOptions = opts;
    });
    this.user.valueChanges.subscribe((u) => {
      this.greeting = '';
      if (u.isAuthenticated) {
        lastValueFrom(this.http.get(greetingApiUri)).then((dto: any) => {
          this.greeting = dto.message;
        });
      }
    });
  }

  get currentUser(): User {
    return this.user.current;
  }

  login() {
    if (this.loginOptions.length !== 1) {
      console.error('Invalid login options count: ', this.loginOptions);
    }
    this.user.login(this.loginOptions[0].loginUri);
  }

  logout() {
    this.user.logout();
  }
}
