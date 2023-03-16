import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http'
import { GatewayApi, LoginOptionDto } from '@c4-soft/gateway-api';
import { BehaviorSubject } from 'rxjs/internal/BehaviorSubject';
import { lastValueFrom } from 'rxjs/internal/lastValueFrom';
import { Observable } from 'rxjs/internal/Observable';

@Injectable({
  providedIn: 'root',
})
export class UserService {
  private user$ = new BehaviorSubject<User>(User.ANONYMOUS);

  constructor(private gatewayApi: GatewayApi, private http: HttpClient) {
    this.refresh();
  }

  refresh(): void {
    this.gatewayApi.getMe().subscribe({
      next: (user) => {
        console.info(user);
        this.user$.next(
          user.subject
            ? new User(
                user.subject,
                user.issuer || '',
                user.roles || []
              )
            : User.ANONYMOUS
        );
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
    lastValueFrom(this.gatewayApi.logout('response')).then((resp) => {
      const logoutUri = resp.headers.get('location') || '';
      if (logoutUri) {
        window.location.href = logoutUri;
      }
    }).finally(() => {
      this.user$.next(User.ANONYMOUS)
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
