import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Subscription, interval, lastValueFrom, map } from 'rxjs';
import { BehaviorSubject } from 'rxjs/internal/BehaviorSubject';
import { Observable } from 'rxjs/internal/Observable';
import { gatewayUri, usersApiUri } from './app.module';

@Injectable({
  providedIn: 'root',
})
export class UserService {
  private user$ = new BehaviorSubject<User>(User.ANONYMOUS);
  private refreshSub?: Subscription;

  constructor(private http: HttpClient) {
    this.refresh();
  }

  refresh(): void {
    this.refreshSub?.unsubscribe();
    this.http.get(`${usersApiUri}/me`).subscribe({
      next: (dto: any) => {
        const user = dto as UserDto;
        this.user$.next(
          user.username
            ? new User(user.username, user.roles || [])
            : User.ANONYMOUS
        );
        if (!!user.username) {
          const now = Date.now();
          const delay = (1000 * user.exp - now) * 0.8;
          if (delay > 2000) {
            this.refreshSub = interval(delay).subscribe(() => this.refresh());
          }
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
    return lastValueFrom(
      this.http.post(`/logout`, null, { observe: 'response' })
    ).then((response) => {
      const location = response.headers.get('Location');
      if (!!location) {
        window.location.href = location;
      }
    });
  }

  async loginOptions(): Promise<Array<LoginOptionDto>> {
    return lastValueFrom(this.http.get(`${gatewayUri}/login-options`)).then(
      (dto) => dto as LoginOptionDto[]
    );
  }

  get valueChanges(): Observable<User> {
    return this.user$;
  }

  get current(): User {
    return this.user$.value;
  }
}

export interface UserDto {
  username: string;
  roles: string[];
  exp: number;
}

export interface LoginOptionDto {
  label: string;
  loginUri: string;
}

export class User {
  static readonly ANONYMOUS = new User('', []);

  constructor(readonly name: string, readonly roles: string[]) {}

  get isAuthenticated(): boolean {
    return !!this.name;
  }

  hasAnyRole(...roles: string[]): boolean {
    for (let r of roles) {
      if (this.roles.includes(r)) {
        return true;
      }
    }
    return false;
  }
}
