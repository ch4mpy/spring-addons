import { NgModule } from '@angular/core';
import { HttpClientModule } from '@angular/common/http';
import { BrowserModule } from '@angular/platform-browser';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';

// If the frontend is not SAMEORIGIN, then prefix the API URI with the gateway domain, but without the protocol prefix,
// otherwise Angular will not provide a CSRF header for POST/DELETE/PUT requests.
// See: https://github.com/angular/angular/issues/20511
// Example: `export const apiUri = '//localhost:8080/bff/v1'`.
export const apiUri = `/bff/v1`;
export const greetingApiUri = `/greeting`;
export const usersApiUri = `/users`;

@NgModule({
  declarations: [
    AppComponent
  ],
  imports: [
    BrowserModule,
    HttpClientModule,
    AppRoutingModule
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
