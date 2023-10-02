import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { GatewayApi, LoginOptionDto } from '@c4-soft/gateway-api';
import { UsersApi } from '@c4-soft/greetings-api';
import { interval } from 'rxjs';
import { BehaviorSubject } from 'rxjs/internal/BehaviorSubject';
import { Observable } from 'rxjs/internal/Observable';
import { Subscription } from 'rxjs/internal/Subscription';
import { lastValueFrom } from 'rxjs/internal/lastValueFrom';

@Injectable({
  providedIn: 'root',
})
export class UserService {
  private user$ = new BehaviorSubject<User>(User.ANONYMOUS);
  private refreshSub?: Subscription;

  constructor(
    private gatewayApi: GatewayApi,
    private usersApi: UsersApi,
    private http: HttpClient
  ) {
    this.refresh();
  }

  refresh(): void {
    this.refreshSub?.unsubscribe()
    this.usersApi.getMe().subscribe({
      next: (user) => {
        this.user$.next(
          user.name
            ? new User(user.name, user.iss || '', user.roles || [])
            : User.ANONYMOUS
        );
        const now = Date.now();
        const delay = (1000 * user.exp - now) * 0.8;
        if (delay > 2000) {
          this.refreshSub = interval(delay).subscribe(() => this.refresh());
        }
      },
      error: (error) => {
        console.warn(error);
        this.user$.next(User.ANONYMOUS);
      },
    });
  }

  login(loginUri: string) {
    window.location.href = loginUri;
  }

  async logout() {
    lastValueFrom(this.gatewayApi.logout('response'))
      .then((resp) => {
        const logoutUri = resp.headers.get('location') || '';
        if (logoutUri) {
          window.location.href = logoutUri;
        }
      })
      .finally(() => {
        this.user$.next(User.ANONYMOUS);
      });
  }

  get loginOptions(): Observable<Array<LoginOptionDto>> {
    return this.gatewayApi.getLoginOptions();
  }

  get valueChanges(): Observable<User> {
    return this.user$;
  }

  get current(): User {
    return this.user$.value;
  }
}

export class User {
  static readonly ANONYMOUS = new User('', '', []);

  constructor(
    readonly subject: string,
    readonly issuer: string,
    readonly roles: string[]
  ) {}

  get isAuthenticated(): boolean {
    return !!this.subject;
  }

  hasAnyRole(...roles: string[]): boolean {
    for (let r in roles) {
      if (this.roles.includes(r)) {
        return true;
      }
    }
    return false;
  }
}
