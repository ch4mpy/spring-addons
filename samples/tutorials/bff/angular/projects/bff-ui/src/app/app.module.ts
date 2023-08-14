import { HttpClientModule } from '@angular/common/http';
import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { ButtonModule } from 'primeng/button';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';

import {
  ApiModule as GatewayApiModule,
  Configuration as GatewayApiConfiguration,
  ConfigurationParameters as GatewayApiConfigurationParameters
} from '@c4-soft/gateway-api';

import {
  ApiModule as GreetingsApiModule,
  Configuration as GreetingsApiConfiguration,
  ConfigurationParameters as GreetingsApiConfigurationParameters
} from '@c4-soft/greetings-api';
import { LoginScreen } from './login.screen';
import { GreetingScreen } from './greeting.screen';



export function gatewayApiConfigFactory(): GatewayApiConfiguration {
  const params: GatewayApiConfigurationParameters = {
    basePath: '',
  };
  return new GatewayApiConfiguration(params);
}

export function greetingsApiConfigFactory(): GreetingsApiConfiguration {
  const params: GreetingsApiConfigurationParameters = {
    basePath: '/bff/greetings-api/v1',
  };
  return new GreetingsApiConfiguration(params);
}

@NgModule({
  declarations: [AppComponent, LoginScreen, GreetingScreen],
  imports: [
    BrowserModule,
    BrowserAnimationsModule,
    HttpClientModule,
    ButtonModule,
    GatewayApiModule.forRoot(gatewayApiConfigFactory),
    GreetingsApiModule.forRoot(greetingsApiConfigFactory),
    AppRoutingModule,
  ],
  providers: [],
  bootstrap: [AppComponent],
})
export class AppModule {}
