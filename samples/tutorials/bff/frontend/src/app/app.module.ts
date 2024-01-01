import { NgModule } from '@angular/core';
import { HttpClientModule } from '@angular/common/http';
import { BrowserModule } from '@angular/platform-browser';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';

export const gatewayUri = 'https://localhost:8080';
// For Angular's HttpClient omit the protocol prefix for POST, DELETE and PUT requests, else Angular will not provide
// an XSRF header. Example: gatewayUri = '//localhost:8080'. See https://github.com/angular/angular/issues/20511
export const apiUri = `${gatewayUri}/bff/v1`;
export const greetingApiUri = `${apiUri}/greeting`;
export const usersApiUri = `${apiUri}/users`;

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
