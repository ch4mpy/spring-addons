import { ChangeDetectorRef, Component, OnInit } from '@angular/core';
import { LoginOptionDto } from '@c4-soft/gateway-api';
import { UserService } from './user.service';

@Component({
  selector: 'app-login',
  template: `
    <div *ngIf="user.current.isAuthenticated">
      <div>
        You are already logged in. Please logout before you can login again.
      </div>
      <a routerLink="/"><button pButton>Main screen</button></a>
      <button pButton (click)="user.logout()">Logout</button>
    </div>
    <div *ngIf="!user.current.isAuthenticated">
      <div>Please select an identity provider:</div>
      <div *ngFor="let opt of loginOptions">
        <button pButton (click)="user.login(opt.loginUri)">
          {{ opt.label }}
        </button>
      </div>
    </div>
  `,
  styles: [],
})
export class LoginScreen implements OnInit {
  loginOptions: LoginOptionDto[] = [];

  constructor(readonly user: UserService, private cdr: ChangeDetectorRef) {}

  ngOnInit(): void {
    this.user.loginOptions.subscribe((opts) => {
      this.loginOptions = opts || [];
      this.cdr.detectChanges();
    });
  }
}
